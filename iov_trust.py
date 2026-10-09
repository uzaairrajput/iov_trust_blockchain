# -*- coding: utf-8 -*-
"""
iov_trust.py - Blockchain-based adaptive trust management for the Internet of
Vehicles (Singh et al., IEEE T-ITS 2020) re-implemented on MultiChain 2.3.3.

Entities (one Windows PC, four MultiChain nodes):
    TA   - Traffic Authority  : admin node, creates streams, grants/revokes
    RSU1 - Road Side Unit 1   : miner, analyses reports, writes trust scores
    RSU2 - Road Side Unit 2   : miner (round-robin with RSU1 and TA)
    VEH  - Vehicle gateway    : holds the addresses of vehicles V1..V6

Usage (run from the folder that holds this file):
    py iov_trust.py setup       one-time: roles, streams, permissions, asset
    py iov_trust.py demo        full scenario: S1, S2, S3, analysis, revocation
    py iov_trust.py status      trust table, credits, permissions, miner rotation

    py iov_trust.py bench 1000  throughput test like the paper (1/100/500/1000)

Individual steps: simulate S1 | simulate S2 | simulate S3 | analyse | enforce

Only Python standard library is used, so it runs on Python 3.4 lab PCs.
"""

import base64
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# CONFIGURATION - change paths/ports here if your setup is different
# ---------------------------------------------------------------------------

CHAIN = "iovchain"
APPDATA = os.environ.get("APPDATA", os.path.expanduser("~"))

NODES = {
    "TA":   {"datadir": os.path.join(APPDATA, "MultiChain"), "rpcport": 7446},
    "RSU1": {"datadir": r"D:\iov\rsu1", "rpcport": 7448},
    "RSU2": {"datadir": r"D:\iov\rsu2", "rpcport": 7450},
    "VEH":  {"datadir": r"D:\iov\veh",  "rpcport": 7452},
}

STREAMS = ["vehicle_registry", "misbehavior_reports", "trust_scores",
           "session_results", "revocations"]

ASSET = "TrustCredit"
VEHICLES = ["V1", "V2", "V3", "V4", "V5", "V6"]
ROLES_FILE = "roles.json"           # public role -> address map
TA_PRIVATE_FILE = "ta_identity_map.json"   # off-chain, TA only (privacy)
ENFORCE_FILE = "enforce_state.json"

INITIAL_TV = 1          # trust value assigned by TA at registration
MIN_REPORTERS = 4       # paper: at least 4 vehicles must report in a session
REWARD_CREDIT = 5       # paper: +5 credit for a true report
ALARMER_BONUS = 2       # paper: +2 credit for the first reporter
BLOCK_SECONDS = 60      # paper: soft revocation blocks a vehicle for 1 minute

# Plausibility limits used at the vehicular plane (future direction)
MAX_SPEED = 70.0            # m/s (about 250 km/h)
SPEED_TOLERANCE = 15.0      # m/s difference between claimed and computed
MAX_HEADING_RATE = 90.0     # degrees per second
MIN_BEACON_GAP = 0.05       # s; CAM/BSM beacons are 1-10 Hz
EVENT_RANGE = 300.0         # m; receivers check claims against own sensors


# ---------------------------------------------------------------------------
# MULTICHAIN JSON-RPC
# ---------------------------------------------------------------------------

class MCError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, "MultiChain error %s: %s" % (code, message))
        self.code = code
        self.message = message


def load_credentials(node):
    conf = os.path.join(NODES[node]["datadir"], CHAIN, "multichain.conf")
    values = {}
    if not os.path.exists(conf):
        raise SystemExit("Cannot find %s - is the %s node created?" % (conf, node))
    with open(conf) as f:
        for line in f:
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip()
    NODES[node]["user"] = values.get("rpcuser", "multichainrpc")
    NODES[node]["password"] = values.get("rpcpassword", "")


def rpc(node, method, *params):
    n = NODES[node]
    if "user" not in n:
        load_credentials(node)
    body = json.dumps({"method": method, "params": list(params),
                       "id": 1, "chain_name": CHAIN}).encode("utf-8")
    req = urllib.request.Request("http://127.0.0.1:%d" % n["rpcport"], data=body)
    req.add_header("Content-Type", "application/json")
    token = base64.b64encode(("%s:%s" % (n["user"], n["password"])).encode("utf-8"))
    req.add_header("Authorization", "Basic " + token.decode("ascii"))
    try:
        raw = urllib.request.urlopen(req, timeout=60).read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 401:
            raise SystemExit("RPC login failed for %s (check multichain.conf)" % node)
        raw = e.read().decode("utf-8")
    except urllib.error.URLError:
        raise SystemExit("Cannot reach %s on port %d - is multichaind running?"
                         % (node, n["rpcport"]))
    out = json.loads(raw)
    if out.get("error"):
        raise MCError(out["error"].get("code"), out["error"].get("message"))
    return out["result"]


def change_perms(action, frm, to, perms):
    """MultiChain accepts only one stream permission per grant/revoke call,
    and global and stream permissions cannot be mixed, so send them one by one."""
    for p in perms.split(","):
        rpc("TA", action, frm, to, p)


def wait_blocks(count=1, timeout=180):
    start_height = rpc("TA", "getblockcount")
    print("   ...waiting for %d new block(s) (height %d)" % (count, start_height))
    started = time.time()
    while rpc("TA", "getblockcount") < start_height + count:
        if time.time() - started > timeout:
            print("   !! no new block after %d s - check that miners are running"
                  % timeout)
            return
        time.sleep(2)


def item_json(item):
    data = item.get("data")
    if isinstance(data, dict) and "json" in data:
        return data["json"]
    return {}


def latest(node, stream, key):
    items = rpc(node, "liststreamkeyitems", stream, key, False, 1)
    if items:
        return item_json(items[-1])
    return None


def save_json(name, obj):
    with open(name, "w") as f:
        json.dump(obj, f, indent=2, sort_keys=True)


def load_json(name, default=None):
    if not os.path.exists(name):
        return default
    with open(name) as f:
        return json.load(f)


def roles():
    r = load_json(ROLES_FILE)
    if r is None:
        raise SystemExit("roles.json missing - run:  py iov_trust.py setup")
    return r


def label_of(r, address):
    for name, addr in r["nodes"].items():
        if addr == address:
            return name
    for name, addr in r["vehicles"].items():
        if addr == address:
            return name
    return address[:10] + "..."


# ---------------------------------------------------------------------------
# SETUP (Traffic Authority initialisation, paper Section V-B)
# ---------------------------------------------------------------------------

def setup():
    print("== SETUP: Traffic Authority initialises the IoV chain ==")
    r = {"nodes": {}, "vehicles": {}}
    for node in ["TA", "RSU1", "RSU2", "VEH"]:
        r["nodes"][node] = rpc(node, "getaddresses")[0]
        print("   %-5s node address %s" % (node, r["nodes"][node]))
    ta = r["nodes"]["TA"]

    # Vehicle pseudonym addresses live in the VEH node wallet
    existing = rpc("VEH", "getaddresses")
    while len(existing) < len(VEHICLES) + 1:
        existing.append(rpc("VEH", "getnewaddress"))
    for i, v in enumerate(VEHICLES):
        r["vehicles"][v] = existing[i + 1]
    save_json(ROLES_FILE, r)

    # 1. Closed streams (write permission must be granted explicitly)
    have = [s["name"] for s in rpc("TA", "liststreams")]
    for s in STREAMS:
        if s not in have:
            rpc("TA", "createfrom", ta, "stream", s, False)
            print("   created closed stream: %s" % s)
    wait_blocks(1)
    for node in NODES:
        rpc(node, "subscribe", STREAMS)

    # 2. Permissions (paper: access-rights modifiers OnlyTA / OnlyRSU / intelligentVehicle)
    rsus = r["nodes"]["RSU1"] + "," + r["nodes"]["RSU2"]
    vehs = ",".join(r["vehicles"][v] for v in VEHICLES)
    change_perms("grantfrom", ta, rsus,
        "send,receive,trust_scores.write,session_results.write,revocations.write")
    change_perms("grantfrom", ta, vehs, "send,receive,misbehavior_reports.write")
    print("   permissions granted to RSUs and vehicles")

    # 3. TrustCredit asset = vehicle wallet score (paper: redeemable credit/ether)
    if not [a for a in rpc("TA", "listassets") if a["name"] == ASSET]:
        rpc("TA", "issuefrom", ta, ta, {"name": ASSET, "open": True}, 100000, 1)
        wait_blocks(1)
        rpc("TA", "sendassetfrom", ta, r["nodes"]["RSU1"], ASSET, 20000)
        rpc("TA", "sendassetfrom", ta, r["nodes"]["RSU2"], ASSET, 20000)
        print("   issued %s and funded both RSU reward pools" % ASSET)

    # 4. Vehicle registration with pseudonyms (paper Fig. 5)
    private_map = {}
    for i, v in enumerate(VEHICLES):
        addr = r["vehicles"][v]
        private_map[addr] = {"label": v, "real_identity": "PLATE-KHI-%03d" % (101 + i)}
        rpc("TA", "publishfrom", ta, "vehicle_registry", addr,
            {"json": {"pseudonym": addr, "region": "R1", "initial_tv": INITIAL_TV,
                      "registered_by": "TA"}})
        rpc("RSU1", "publishfrom", r["nodes"]["RSU1"], "trust_scores", addr,
            {"json": {"vehicle": v, "tv": INITIAL_TV, "status": "active",
                      "reason": "registration", "rsu": "RSU1"}})
    save_json(TA_PRIVATE_FILE, private_map)
    print("   6 vehicles registered (real identities kept off-chain by TA)")
    wait_blocks(1)
    print("== SETUP COMPLETE ==")


# ---------------------------------------------------------------------------
# VEHICULAR PLANE: beacons + plausibility checks (future direction 1)
# ---------------------------------------------------------------------------

def make_beacons(kind):
    """Return a list of beacons (t, x, y, speed, heading) for one sender."""
    if kind == "normal":
        return [{"t": 0.0, "x": 100.0, "y": 0.0, "speed": 20.0, "heading": 90.0},
                {"t": 1.0, "x": 120.0, "y": 0.0, "speed": 20.0, "heading": 90.0},
                {"t": 2.0, "x": 140.0, "y": 0.0, "speed": 20.0, "heading": 92.0}]
    if kind == "teleport":      # position jumps 400 m in one second
        return [{"t": 0.0, "x": 80.0, "y": 0.0, "speed": 22.0, "heading": 90.0},
                {"t": 1.0, "x": 480.0, "y": 0.0, "speed": 22.0, "heading": 90.0},
                {"t": 2.0, "x": 502.0, "y": 0.0, "speed": 22.0, "heading": 90.0}]
    if kind == "erratic":       # impossible speed, heading flip, beacon flood
        return [{"t": 0.0, "x": 200.0, "y": 0.0, "speed": 95.0, "heading": 90.0},
                {"t": 0.01, "x": 201.0, "y": 0.0, "speed": 95.0, "heading": 270.0},
                {"t": 1.0, "x": 230.0, "y": 0.0, "speed": 95.0, "heading": 90.0}]
    raise ValueError(kind)


def plausibility(beacons, claim, own_view):
    """Local misbehaviour detection run by a receiving vehicle."""
    issues = []
    for b in beacons:
        if b["speed"] > MAX_SPEED:
            issues.append("claimed speed %.0f m/s exceeds %.0f m/s"
                          % (b["speed"], MAX_SPEED))
            break
    for a, b in zip(beacons, beacons[1:]):
        dt = b["t"] - a["t"]
        if dt < MIN_BEACON_GAP:
            issues.append("beacon interval %.2f s is too short (flooding)" % dt)
            continue
        dist = math.hypot(b["x"] - a["x"], b["y"] - a["y"])
        moved = dist / dt
        if moved > MAX_SPEED:
            issues.append("position jump %.0f m in %.1f s" % (dist, dt))
        elif abs(moved - b["speed"]) > SPEED_TOLERANCE:
            issues.append("speed inconsistent with movement")
        turn = abs((b["heading"] - a["heading"] + 180) % 360 - 180)
        if turn / dt > MAX_HEADING_RATE:
            issues.append("heading change %.0f deg in %.2f s" % (turn, dt))
    if claim and own_view:
        near = abs(own_view["event_x"] - claim["x"]) <= EVENT_RANGE
        if near and claim["type"] != own_view["sees"]:
            issues.append("content conflict: claims %s, own sensors see %s"
                          % (claim["type"], own_view["sees"]))
    return issues


SCENARIOS = {
    # S1: V6 broadcasts ROAD_CLEAR near a real accident (paper Fig. 1)
    "S1": {"sender": "V6", "kind": "teleport",
           "claim": {"type": "ROAD_CLEAR", "x": 480.0},
           "observers": ["V1", "V2", "V3", "V5"],
           "own_view": {"event_x": 500.0, "sees": "ACCIDENT"},
           "duplicate_from": "V1"},
    # S2: dishonest V4 alone accuses benign V2 (paper's 4-reporter rule)
    "S2": {"sender": "V2", "kind": "normal",
           "claim": {"type": "TRAFFIC_JAM", "x": 140.0},
           "observers": [], "false_accuser": "V4",
           "own_view": {"event_x": 140.0, "sees": "TRAFFIC_JAM"}},
    # S3: V6 misbehaves again with a fake congestion warning
    "S3": {"sender": "V6", "kind": "erratic",
           "claim": {"type": "TRAFFIC_JAM", "x": 230.0},
           "observers": ["V1", "V2", "V3", "V5"],
           "own_view": {"event_x": 230.0, "sees": "ROAD_CLEAR"}},
}


def publish_report(r, reporter, session, suspect, beacons, claim, issues):
    data = {"session": session, "reporter": reporter,
            "suspect": r["vehicles"][suspect], "claim": claim,
            "beacons": beacons, "issues": issues, "time": int(time.time())}
    rpc("VEH", "publishfrom", r["vehicles"][reporter], "misbehavior_reports",
        session, {"json": data})


def simulate(session):
    r = roles()
    sc = SCENARIOS[session]
    print("== EVENT %s: %s broadcasts %s ==" % (session, sc["sender"], sc["claim"]["type"]))
    beacons = make_beacons(sc["kind"])
    for obs in sc["observers"]:
        issues = plausibility(beacons, sc["claim"], sc["own_view"])
        if issues:
            publish_report(r, obs, session, sc["sender"], beacons, sc["claim"], issues)
            print("   %s -> reportSuspicion(%s): %s" % (obs, sc["sender"], "; ".join(issues)))
        else:
            print("   %s found the message plausible, no report" % obs)
    if sc.get("duplicate_from"):
        d = sc["duplicate_from"]
        publish_report(r, d, session, sc["sender"], beacons, sc["claim"],
                       plausibility(beacons, sc["claim"], sc["own_view"]))
        print("   %s sent a duplicate report (RSU must ignore it)" % d)
    if sc.get("false_accuser"):
        liar = sc["false_accuser"]
        publish_report(r, liar, session, sc["sender"], beacons, sc["claim"],
                       ["(fabricated) position jump"])
        print("   %s falsely accuses %s with fabricated evidence" % (liar, sc["sender"]))


def attempt_report(attacker, victim, session):
    r = roles()
    print("   %s tries to publish a counter-report against %s ..." % (attacker, victim))
    try:
        publish_report(r, attacker, session, victim, make_beacons("normal"),
                       None, ["(revenge report)"])
        print("   !! accepted - permissions were NOT enforced")
    except MCError as e:
        print("   REJECTED by MultiChain: %s" % e.message)


# ---------------------------------------------------------------------------
# RSU PLANE: report analysis, trust update, rewards (paper Algorithms 2 and 3)
# ---------------------------------------------------------------------------

def analyse(rsu="RSU1"):
    r = roles()
    me = r["nodes"][rsu]
    print("== %s analyseReports() ==" % rsu)
    done = set(i["keys"][0] for i in rpc(rsu, "liststreamitems", "session_results",
                                         False, 10000))
    items = rpc(rsu, "liststreamitems", "misbehavior_reports", False, 10000)
    sessions = {}
    for it in items:
        sessions.setdefault(it["keys"][0], []).append(it)

    for session in sorted(sessions):
        if session in done or session.startswith("X") or session.startswith("BENCH"):
            continue
        reports, seen, duplicates, rejected = [], set(), 0, 0
        for it in sessions[session]:
            d = item_json(it)
            reporter_addr = it["publishers"][0]
            pair = (reporter_addr, d.get("suspect"))
            if pair in seen:
                duplicates += 1
                continue
            seen.add(pair)
            # RSU re-runs plausibility on the evidence stored on-chain
            if not plausibility(d.get("beacons", []), None, None) and \
                    not [x for x in d.get("issues", []) if x.startswith("content")]:
                rejected += 1
                continue
            reports.append((reporter_addr, d))
        count = len(seen)
        score = {}
        for reporter_addr, d in reports:
            score[d["suspect"]] = score.get(d["suspect"], 0) + 1
        verdicts = {}
        for suspect, s in score.items():
            verdicts[suspect] = (count >= MIN_REPORTERS and s > count / 2.0)
        print("   session %s: %d reporters, %d duplicate(s) ignored, %d report(s) "
              "with unverifiable evidence" % (session, count, duplicates, rejected))

        if not verdicts:
            print("   -> no action: no report in this session had verifiable evidence")
        for suspect, guilty in verdicts.items():
            name = label_of(r, suspect)
            if not guilty:
                print("   -> %s NOT punished (needs >= %d reporters and majority)"
                      % (name, MIN_REPORTERS))
                continue
            current = latest(rsu, "trust_scores", suspect) or {"tv": INITIAL_TV}
            tv = current["tv"] - 1
            status = "revoked" if tv < 0 else "blocked"
            rpc(rsu, "publishfrom", me, "trust_scores", suspect,
                {"json": {"vehicle": name, "tv": tv, "status": status,
                          "session": session, "rsu": rsu,
                          "blocked_until": int(time.time()) + BLOCK_SECONDS}})
            kind = "hard" if tv < 0 else "soft"
            rpc(rsu, "publishfrom", me, "revocations", suspect,
                {"json": {"vehicle": name, "type": kind, "session": session,
                          "tv": tv, "rsu": rsu,
                          "until": int(time.time()) + BLOCK_SECONDS}})
            print("   -> %s judged MISBEHAVING: TV %d -> %d, %s revocation requested"
                  % (name, current["tv"], tv, kind))

            # Rewards for honest reporters (Algorithm 3)
            alarmer = reports[0][0] if reports else None
            for reporter_addr, d in reports:
                if d["suspect"] != suspect:
                    continue
                rname = label_of(r, reporter_addr)
                credit = REWARD_CREDIT + (ALARMER_BONUS if reporter_addr == alarmer else 0)
                rtv = (latest(rsu, "trust_scores", reporter_addr) or
                       {"tv": INITIAL_TV})["tv"] + 1
                rpc(rsu, "sendassetfrom", me, reporter_addr, ASSET, credit)
                rpc(rsu, "publishfrom", me, "trust_scores", reporter_addr,
                    {"json": {"vehicle": rname, "tv": rtv, "status": "active",
                              "session": session, "rsu": rsu,
                              "reason": "true report reward"}})
                print("      reward %s: +%d %s, TV -> %d%s" % (
                    rname, credit, ASSET, rtv,
                    " (alarmer bonus)" if reporter_addr == alarmer else ""))

        rpc(rsu, "publishfrom", me, "session_results", session,
            {"json": {"session": session, "reporters": count,
                      "verdicts": dict((label_of(r, k), v) for k, v in verdicts.items()),
                      "analysed_by": rsu}})
    wait_blocks(1)


# ---------------------------------------------------------------------------
# TA: enforce soft / hard revocation with MultiChain permissions
# ---------------------------------------------------------------------------

def enforce():
    r = roles()
    ta = r["nodes"]["TA"]
    state = load_json(ENFORCE_FILE, {})
    print("== TA enforces revocations ==")
    for it in rpc("TA", "liststreamitems", "revocations", False, 10000):
        d = item_json(it)
        addr = it["keys"][0]
        key = "%s|%s" % (addr, d.get("session"))
        if key in state:
            continue
        if d["type"] == "hard":
            change_perms("revokefrom", ta, addr, "send,receive,misbehavior_reports.write")
            print("   HARD revocation of %s (TV %d): send/receive/write removed "
                  "permanently" % (d["vehicle"], d["tv"]))
        else:
            change_perms("revokefrom", ta, addr, "send,misbehavior_reports.write")
            print("   SOFT revocation of %s: blocked for %d s" % (d["vehicle"], BLOCK_SECONDS))
        state[key] = {"type": d["type"], "until": d.get("until", 0), "addr": addr,
                      "vehicle": d["vehicle"], "restored": False}
    # restore soft-blocked vehicles whose time is over (unless hard revoked)
    hard = set(v["addr"] for v in state.values() if v["type"] == "hard")
    for key, v in state.items():
        if v["type"] == "soft" and not v["restored"] and v["addr"] not in hard \
                and time.time() >= v["until"]:
            change_perms("grantfrom", ta, v["addr"], "send,misbehavior_reports.write")
            v["restored"] = True
            print("   soft block of %s expired: permissions restored" % v["vehicle"])
    save_json(ENFORCE_FILE, state)
    wait_blocks(1)


# ---------------------------------------------------------------------------
# STATUS
# ---------------------------------------------------------------------------

def status():
    r = roles()
    print("== TRUST TABLE (latest trust_scores item per vehicle) ==")
    print("   %-4s %-36s %4s  %-8s %8s  %s" % ("Veh", "Pseudonym address", "TV",
                                              "Status", "Credits", "Can send?"))
    send_ok = set(p["address"] for p in rpc("TA", "listpermissions", "send"))
    for v in VEHICLES:
        addr = r["vehicles"][v]
        t = latest("TA", "trust_scores", addr) or {}
        credits = 0
        for b in rpc("VEH", "getaddressbalances", addr):
            if b["name"] == ASSET:
                credits = b["qty"]
        print("   %-4s %-36s %4s  %-8s %8s  %s" % (
            v, addr, t.get("tv"), t.get("status"), credits,
            "yes" if addr in send_ok else "NO"))

    height = rpc("TA", "getblockcount")
    first = max(1, height - 11)
    blocks = rpc("TA", "listblocks", "%d-%d" % (first, height))
    print("\n== MINER ROTATION (last %d blocks, mining-diversity) ==" % len(blocks))
    print("   " + "  ".join("%d:%s" % (b["height"], label_of(r, b["miner"]))
                            for b in blocks))
    params = rpc("TA", "getblockchainparams")
    print("\n   mining-diversity=%s  target-block-time=%s  anyone-can-connect=%s"
          % (params.get("mining-diversity"), params.get("target-block-time"),
             params.get("anyone-can-connect")))



# ---------------------------------------------------------------------------
# BENCHMARK (same metrics as the paper, Section VI: execution time, throughput)
# ---------------------------------------------------------------------------

def bench(n):
    r = roles()
    sender = r["vehicles"]["V1"]
    key = "BENCH-%d-%d" % (n, int(time.time()))
    print("== BENCHMARK: %d reportSuspicion transactions from V1 ==" % n)
    t1 = time.time()
    for i in range(n):
        rpc("VEH", "publishfrom", sender, "misbehavior_reports", key,
            {"json": {"session": key, "seq": i, "suspect": r["vehicles"]["V6"],
                      "issues": ["benchmark"]}})
    sent = time.time() - t1
    print("   all %d transactions submitted in %.2f s, waiting for confirmation..."
          % (n, sent))
    while True:
        items = rpc("TA", "liststreamkeyitems", "misbehavior_reports", key, False, n)
        if len(items) >= n and min(it.get("confirmations", 0) for it in items) > 0:
            break
        if time.time() - t1 > 1800:
            print("   !! timeout")
            return
        time.sleep(0.5)
    total = max(time.time() - t1, 0.001)
    print("   execution time (first submit -> last mined): %.2f s" % total)
    print("   average throughput: %.2f tx/s" % (n / total))
    with open("bench_results.csv", "a") as f:
        f.write("%d,%.2f,%.2f\n" % (n, total, n / total))

# ---------------------------------------------------------------------------
# DEMO
# ---------------------------------------------------------------------------

def demo():
    simulate("S1")
    wait_blocks(1)
    analyse("RSU1")
    enforce()
    attempt_report("V6", "V1", "X1")      # soft-blocked vehicle cannot write
    simulate("S2")
    simulate("S3")
    wait_blocks(1)
    analyse("RSU2")                       # second RSU continues the analysis
    enforce()
    attempt_report("V6", "V2", "X2")      # hard-revoked vehicle cannot write
    print("")
    status()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == "setup":
        setup()
    elif cmd == "simulate":
        simulate(sys.argv[2])
    elif cmd == "analyse":
        analyse(sys.argv[2] if len(sys.argv) > 2 else "RSU1")
    elif cmd == "enforce":
        enforce()
    elif cmd == "status":
        status()
    elif cmd == "demo":
        demo()
    elif cmd == "bench":
        bench(int(sys.argv[2]) if len(sys.argv) > 2 else 100)
    else:
        print(__doc__)


if __name__ == "__main__":
    main()