from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from .agent import network_agent
from scapy.all import IP, TCP, UDP, send, RandIP

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    interface: str = "lo"

class AttackRequest(BaseModel):
    target: str = "127.0.0.1"
    count: int = 500

@app.post("/analyze")
def analyze_network(req: ScanRequest):
    result = network_agent.invoke({
        "interface": req.interface,
        "packets": [],
        "stats": {},
        "ai_summary": "",
        "threats": []
    })
    return {
        "stats": result["stats"],
        "threats": result["threats"],
        "ai_summary": result["ai_summary"]
    }

@app.post("/attack/ddos")
def attack_ddos(req: AttackRequest):
    send(IP(src="1.2.3.4", dst=req.target)/UDP(dport=80), count=req.count, verbose=0)
    return {"status": "sent", "packets": req.count, "type": "DDoS"}

@app.post("/attack/portscan")
def attack_portscan(req: AttackRequest):
    for port in range(1, 40):
        send(IP(src="5.5.5.5", dst=req.target)/TCP(dport=port, flags="S"), verbose=0)
    return {"status": "sent", "ports": 39, "type": "Port Scan"}

@app.post("/attack/synflood")
def attack_synflood(req: AttackRequest):
    send(IP(src=RandIP(), dst=req.target)/TCP(dport=443, flags="S"), count=req.count, verbose=0)
    return {"status": "sent", "packets": req.count, "type": "SYN Flood"}

@app.post("/attack/suspicious")
def attack_suspicious(req: AttackRequest):
    for port in [22, 4444, 6666, 3389, 9001]:
        send(IP(src="9.9.9.9", dst=req.target)/TCP(dport=port, flags="S"), count=10, verbose=0)
    return {"status": "sent", "ports": [22, 4444, 6666, 3389, 9001], "type": "Suspicious Ports"}

@app.post("/attack/normal")
def attack_normal(req: AttackRequest):
    send(IP(src="192.168.1.1", dst=req.target)/TCP(dport=80, flags="S"), count=30, verbose=0)
    send(IP(src="192.168.1.2", dst=req.target)/TCP(dport=443, flags="S"), count=30, verbose=0)
    return {"status": "sent", "packets": 60, "type": "Normal Traffic"}

@app.get("/health")
def health():
    return {"status": "ok"}