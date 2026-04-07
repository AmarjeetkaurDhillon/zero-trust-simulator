from flask import Flask, render_template, request, jsonify
from policy_engine import evaluate_request, calculate_blast_radius, generate_simulation_scenarios, POLICIES
from datetime import datetime

app = Flask(__name__)

access_log = []

@app.route("/")
def index():
    scenarios = generate_simulation_scenarios()
    results = []
    for scenario in scenarios:
        result = evaluate_request(scenario)
        blast = calculate_blast_radius(scenario, result["action"])
        results.append({
            "scenario": scenario,
            "result": result,
            "blast_radius": blast
        })
    return render_template("index.html", 
                         results=results,
                         policies=POLICIES,
                         access_log=access_log[-20:])

@app.route("/evaluate", methods=["POST"])
def evaluate():
    data = request.json
    data["hour"] = datetime.now().hour
    result = evaluate_request(data)
    blast = calculate_blast_radius(data, result["action"])
    
    log_entry = {
        "timestamp": result["timestamp"],
        "user": data.get("user", "unknown"),
        "action": result["action"],
        "reason": result["reason"],
        "risk_score": result["risk_score"]
    }
    access_log.append(log_entry)
    
    return jsonify({
        "result": result,
        "blast_radius": blast
    })

@app.route("/api/policies")
def get_policies():
    return jsonify([{
        "id": p["id"],
        "name": p["name"],
        "description": p["description"],
        "action": p["action"]
    } for p in POLICIES])

if __name__ == "__main__":
    app.run(debug=True)