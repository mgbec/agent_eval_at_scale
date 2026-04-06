"""AgentCore Runtime entrypoint for the triage agent."""

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from src.agents.triage_agent import create_triage_agent

app = BedrockAgentCoreApp()
agent = create_triage_agent(callback_handler=None)


@app.entrypoint
def invoke(payload):
    """Process a triage request and return the agent's response."""
    prompt = payload.get("prompt", "")
    if not prompt:
        return {"error": "No prompt provided. Include a 'prompt' key in the payload."}
    result = agent(prompt)
    return {"result": result.message}


if __name__ == "__main__":
    app.run()
