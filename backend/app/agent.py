import os
from langgraph.graph import StateGraph
from typing import TypedDict
from dotenv import load_dotenv
from google import genai
from .capture import capture_packets
from .analyzer import analyze_packets

load_dotenv()
client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))

class NetworkState(TypedDict):
    interface: str
    packets: list
    stats: dict
    ai_summary: str
    threats: list

def capture_node(state: NetworkState):
    packets = capture_packets(state["interface"], count=200)
    return {"packets": packets}

def analyze_node(state: NetworkState):
    stats = analyze_packets(state["packets"])
    return {"stats": stats, "threats": stats.get("threats", [])}

def ai_summary_node(state: NetworkState):
    stats = state["stats"]
    threats = state["threats"]

    try:
        prompt = f"""
You are a network security analyst. Analyze this network data and give a concise 1-page report.

Stats:
- Total packets: {stats.get('total_packets')}
- Total bytes: {stats.get('total_bytes')}
- Protocols: {stats.get('protocols')}
- Top sources: {stats.get('top_sources')}
- Top ports: {stats.get('top_ports')}

Detected threats: {threats if threats else 'None'}

Give:
1. Network health summary (2-3 sentences)
2. Key observations (3-4 bullets)
3. Threat assessment
4. Recommended actions

Keep it under 300 words.
"""
        response = client.models.generate_content(
            model="gemini-1.5-flash-8b",  # lightest model, least overloaded
            contents=prompt
        )
        return {"ai_summary": response.text}

    except Exception as e:
        error_msg = str(e)
        if "503" in error_msg:
            msg = "Gemini server busy — try again in 30 seconds."
        elif "429" in error_msg:
            msg = "API quota exceeded — wait 24 hours or use a new key."
        else:
            msg = f"AI unavailable: {error_msg[:80]}"
        return {"ai_summary": msg}


# Build graph
graph = StateGraph(NetworkState)
graph.add_node("capture", capture_node)
graph.add_node("analyze", analyze_node)
graph.add_node("ai_summary", ai_summary_node)

graph.set_entry_point("capture")
graph.add_edge("capture", "analyze")
graph.add_edge("analyze", "ai_summary")
graph.set_finish_point("ai_summary")

network_agent = graph.compile()