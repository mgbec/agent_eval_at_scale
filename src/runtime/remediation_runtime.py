"""AgentCore Runtime entrypoint for the remediation agent."""

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from src.agents.remediation_agent import create_remediation_agent

app = BedrockAgentCoreApp()
agent = create_remediation_agent(callback_handler=None)


@app.entrypoint
def invoke(payload):
    """Process a remediation request and return the agent's response."""
    prompt = payload.get("prompt", "")
    if not prompt:
        return {"error": "No prompt provided. Include a 'prompt' key in the payload."}
    result = agent(prompt)
    return {"result": result.message}


if __name__ == "__main__":
    app.run()
