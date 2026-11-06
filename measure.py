import json, sys, time, uuid, urllib.request

BASE = "http://127.0.0.1:8001"
path = sys.argv[1]

boundary = uuid.uuid4().hex
data = open(path, "rb").read()
name = path.replace("\\", "/").split("/")[-1]
head = ('--' + boundary + '\r\nContent-Disposition: form-data; name="file"; filename="' + name + '"\r\nContent-Type: text/plain\r\n\r\n').encode()
tail = ('\r\n--' + boundary + '--\r\n').encode()
body = head + data + tail
req = urllib.request.Request(BASE + "/upload", body, {"Content-Type": "multipart/form-data; boundary=" + boundary})
job = json.load(urllib.request.urlopen(req))["job_id"]
print("job:", job)

urllib.request.urlopen(urllib.request.Request(BASE + "/jobs/" + job + "/start", method="POST"))

peak = 0
start = time.time()
while True:
    p = json.load(urllib.request.urlopen(BASE + "/jobs/" + job))
    peak = max(peak, p.get("ram_used_mb") or 0)
    print(str(p["completed_chunks"]) + "/" + str(p["total_chunks"]) + "  RAM " + str(p.get("ram_used_mb")) + " MB", end="\r")
    done = p["report_available"]
    failed = p["status"] == "failed"
    if done or failed:
        break
    time.sleep(2)

print()
print("Status=" + str(p["status"]), "Chunks=" + str(p["total_chunks"]), "PeakRAM_MB=" + str(peak), "Seconds=" + str(int(time.time() - start)))
if done:
    rep = json.load(urllib.request.urlopen(BASE + "/jobs/" + job + "/report"))
    for f in rep["findings"]:
        print(f["severity"], f["attack_type"], f["entity"], f["evidence_lines"][:6])
else:
    print("Error:", p.get("error"))
