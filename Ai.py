import os
import json
from typing import Union, List, Optional
from pydantic import BaseModel
from fastapi import HTTPException
from openai import AsyncOpenAI

# Environment and Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")

# Initialize Async OpenAI Client
client = AsyncOpenAI(api_key=OPENAI_API_KEY)

# --- AI ANALYST SCHEMAS ---
class AIAnalysisRequest(BaseModel):
    context: Union[dict, List[dict]]
    mode: str = "single"

class AIChatRequest(BaseModel):
    message: str
    context: dict

class CompareTrendsRequest(BaseModel):
    base_id: int
    target_id: int

# --- CORE LOGIC FUNCTIONS ---

async def call_openai_analyst(prompt: str, system_instruction: str, json_mode: bool = True):
    if not OPENAI_API_KEY:
        raise HTTPException(status_code=500, detail="OpenAI API Key not configured")
    try:
        response_format = {"type": "json_object"} if json_mode else None
        response = await client.chat.completions.create(
            model="gpt-4o", 
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1, 
            response_format=response_format
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"OpenAI API Call Failed: {e}")
        if json_mode:
            return json.dumps({
                "summary": "Neural synthesis interrupted.",
                "root_cause": "Core timeout.",
                "risk": "Operational blindness.", 
                "opportunity": "Synthesis interrupted.", 
                "action": "Refresh and retry.",
                "roi_impact": "Unknown",
                "confidence": 0.0
            })
        return "I encountered an error processing that request."

async def run_ai_analysis(payload, user):
    org = user.organization if user.organization else "the organization"
    ind = user.industry if user.industry else "the current sector"
    exec_name = user.first_name if user.first_name else "Executive"

    few_shot = (
        "EXAMPLE_INPUT: Customer churn increased 5% in the Enterprise segment this month.\n"
        "EXAMPLE_OUTPUT: {"
        "\"summary\": \"Enterprise churn spike detected, threatening core recurring revenue.\", "
        "\"root_cause\": \"Technical friction in the API integration layer for Tier-1 clients.\", "
        "\"risk\": \"The current escalation in churn suggests a potential loss of $2M in LTV...\", "
        "\"opportunity\": \"By automating the API troubleshooting, we can improve retention by 12%...\", "
        "\"action\": \"Immediately deploy the engineering task force to patch the integration gateway...\", "
        "\"roi_impact\": \"-$120,000 ARR risk prevention\", "
        "\"confidence\": 0.94}"
    )

    system_prompt = (
        f"You are the world's best Lead Strategic Data Analyst at {org}, specializing in {ind}. "
        f"You are reporting to {exec_name}. Provide an elite executive-level analysis. "
        "Respond ONLY in valid JSON.\n\n"
        f"{few_shot}\n\n"
        "REQUIRED KEYS: 'summary', 'root_cause', 'risk', 'opportunity', 'action', 'roi_impact', 'confidence'.\n"
        "CONSTRAINTS: 'risk', 'opportunity', 'action' MUST be detailed paragraphs (MIN 3 sentences)."
    )
    user_prompt = f"Data Context: {json.dumps(payload.context)}."
    
    raw_ai_response = await call_openai_analyst(user_prompt, system_prompt, json_mode=True)
    parsed_response = json.loads(raw_ai_response)
    if "executive_summary" in parsed_response and "summary" not in parsed_response:
        parsed_response["summary"] = parsed_response["executive_summary"]
    return parsed_response

async def run_ai_chat(payload, user):
    org_ctx = f"The user works at {user.organization}." if user.organization else ""
    ind_ctx = f"Industry: {user.industry}." if user.industry else ""
    exec_name = user.first_name if user.first_name else "Client"
    
    system_prompt = (
        f"You are MetriaAI, an elite data analyst for {exec_name}. {org_ctx} {ind_ctx} "
        "Answer questions based on the provided data context with high precision."
    )
    user_prompt = f"Context: {json.dumps(payload.context)}\n\nQuestion: {payload.message}"
    return await call_openai_analyst(user_prompt, system_instruction=system_prompt, json_mode=False)

async def run_trend_comparison(base_data, target_data):
    system_prompt = (
        "You are a Strategic Growth Specialist. Compare these two historical reports. "
        "Identify metrics drift, performance improvements, and emerging delta-risks. "
        "Limit to 3 powerful, data-backed sentences."
    )
    user_prompt = f"Previous Analysis: {json.dumps(base_data)}\nCurrent Analysis: {json.dumps(target_data)}"
    return await call_openai_analyst(user_prompt, system_prompt, json_mode=False)