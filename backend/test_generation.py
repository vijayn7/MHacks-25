"""
Test Generation API endpoints for agentic chat interface
"""

import os
import json
import uuid
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

# Configure Gemini
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-2.5-pro')

router = APIRouter()

class TestGenerationRequest(BaseModel):
    user_request: str
    target_url: str
    conversation_history: List[Dict[str, Any]]
    codebase_path: Optional[str] = None

class TestGenerationResponse(BaseModel):
    success: bool
    response: str
    suggestions: List[str]
    testRequest: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

class WorkflowTriggerRequest(BaseModel):
    user_request: str
    target_url: str
    test_description: str
    attack_categories: List[str]
    codebase_path: Optional[str] = None

class WorkflowStatusResponse(BaseModel):
    status: str  # 'pending', 'running', 'completed', 'failed'
    workflowId: str
    findingsCount: int = 0
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

@router.post("/generate-tests", response_model=TestGenerationResponse)
async def generate_tests(request: TestGenerationRequest):
    """
    Generate test suggestions and create test request based on user input
    """
    try:
        # Prepare context for Gemini
        context = f"""
        User wants to test: {request.user_request}
        Target URL: {request.target_url}
        
        Conversation history:
        {json.dumps(request.conversation_history, indent=2)}
        
        You are an AI security testing assistant. Based on the user's request, provide:
        1. A helpful response acknowledging their request
        2. Specific test suggestions related to their request
        3. A structured test request that can be used to generate actual test cases
        
        Focus on security testing areas like:
        - Authentication and authorization bypass
        - Input validation and injection attacks
        - Business logic flaws
        - Data access controls
        - API security
        - Session management
        - File upload vulnerabilities
        - Race conditions
        - Privilege escalation
        """
        
        prompt = f"""
        {context}
        
        Respond with a JSON object containing:
        {{
            "response": "Your helpful response to the user",
            "suggestions": ["suggestion1", "suggestion2", "suggestion3"],
            "testRequest": {{
                "description": "Clear description of what will be tested",
                "attack_categories": ["category1", "category2"],
                "target_url": "{request.target_url}",
                "user_request": "{request.user_request}",
                "priority": "high|medium|low"
            }}
        }}
        
        Make the response conversational and helpful. The suggestions should be specific test ideas related to their request.
        """
        
        response = model.generate_content(prompt)
        
        # Parse Gemini response
        response_text = response.text.strip()
        
        # Extract JSON from response
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Find JSON object in response
        start_idx = response_text.find('{')
        end_idx = response_text.rfind('}')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            response_text = response_text[start_idx:end_idx + 1]
        
        try:
            parsed_response = json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            parsed_response = {
                "response": response_text,
                "suggestions": [
                    "Test authentication bypass methods",
                    "Check for authorization flaws",
                    "Test input validation",
                    "Look for business logic vulnerabilities"
                ],
                "testRequest": {
                    "description": f"Security testing for: {request.user_request}",
                    "attack_categories": ["authentication", "authorization", "input_validation"],
                    "target_url": request.target_url,
                    "user_request": request.user_request,
                    "priority": "medium"
                }
            }
        
        return TestGenerationResponse(
            success=True,
            response=parsed_response.get("response", response_text),
            suggestions=parsed_response.get("suggestions", []),
            testRequest=parsed_response.get("testRequest")
        )
        
    except Exception as e:
        return TestGenerationResponse(
            success=False,
            response="I apologize, but I encountered an error processing your request.",
            suggestions=[],
            error=str(e)
        )

@router.post("/trigger-workflow", response_model=WorkflowStatusResponse)
async def trigger_workflow(request: WorkflowTriggerRequest):
    """
    Trigger GitHub workflow to generate and execute test cases
    """
    try:
        workflow_id = str(uuid.uuid4())
        
        # Import GitHub workflow trigger
        from github_workflow_trigger import GitHubWorkflowTrigger
        
        # Prepare workflow inputs
        workflow_inputs = {
            "user_request": request.user_request,
            "target_url": request.target_url,
            "test_description": request.test_description,
            "attack_categories": ",".join(request.attack_categories),
            "codebase_path": request.codebase_path or "",
            "workflow_id": workflow_id
        }
        
        # Trigger the GitHub workflow
        trigger = GitHubWorkflowTrigger()
        result = trigger.trigger_workflow(workflow_inputs)
        
        if result["success"]:
            return WorkflowStatusResponse(
                status="pending",
                workflowId=workflow_id,
                findingsCount=0
            )
        else:
            raise HTTPException(status_code=500, detail=f"Failed to trigger workflow: {result.get('error', 'Unknown error')}")
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to trigger workflow: {str(e)}")

@router.get("/workflow-status/{workflow_id}", response_model=WorkflowStatusResponse)
async def get_workflow_status(workflow_id: str):
    """
    Get the status of a running workflow
    """
    try:
        # Import GitHub workflow trigger
        from github_workflow_trigger import GitHubWorkflowTrigger
        
        # Get workflow status from GitHub
        trigger = GitHubWorkflowTrigger()
        
        # For demo purposes, we'll simulate the workflow status
        # In a real implementation, you would:
        # 1. Query GitHub API for workflow status
        # 2. Check for completed test results
        # 3. Download and parse artifacts if completed
        
        import random
        import time
        
        # Simulate workflow progression based on time
        current_time = time.time()
        workflow_start_time = current_time - random.randint(60, 300)  # Started 1-5 minutes ago
        
        # Determine status based on elapsed time
        elapsed_minutes = (current_time - workflow_start_time) / 60
        
        if elapsed_minutes < 2:
            status = "pending"
        elif elapsed_minutes < 5:
            status = "running"
        else:
            status = "completed"
        
        if status == "completed":
            # Simulate test results
            findings_count = random.randint(0, 5)
            results = {
                "findings": [
                    {
                        "id": f"finding_{i}",
                        "title": f"Security Issue {i+1}",
                        "severity": random.choice(["critical", "high", "medium", "low"]),
                        "description": f"Description of security issue {i+1}",
                        "evidence": f"Evidence for issue {i+1}",
                        "fix": f"Recommended fix for issue {i+1}"
                    }
                    for i in range(findings_count)
                ],
                "summary": {
                    "total_tests": random.randint(10, 50),
                    "vulnerabilities_found": findings_count,
                    "execution_time": f"{random.randint(2, 8)} minutes"
                }
            }
            
            return WorkflowStatusResponse(
                status=status,
                workflowId=workflow_id,
                findingsCount=findings_count,
                results=results
            )
        elif status == "failed":
            return WorkflowStatusResponse(
                status=status,
                workflowId=workflow_id,
                error="Workflow execution failed"
            )
        else:
            return WorkflowStatusResponse(
                status=status,
                workflowId=workflow_id,
                findingsCount=0
            )
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get workflow status: {str(e)}")

@router.post("/generate-detailed-tests")
async def generate_detailed_tests(request: WorkflowTriggerRequest):
    """
    Generate detailed test cases using Gemini AI
    This would be called by the GitHub workflow
    """
    try:
        # This endpoint would be called by the GitHub workflow
        # to generate specific test cases based on the user's request
        
        prompt = f"""
        Generate detailed security test cases for the following request:
        
        User Request: {request.user_request}
        Target URL: {request.target_url}
        Attack Categories: {', '.join(request.attack_categories)}
        
        Generate 5-10 specific, executable test cases that can be automated.
        For each test case, provide:
        1. Test name and description
        2. Specific attack payloads or techniques
        3. Expected behavior if vulnerable
        4. Risk level (Critical/High/Medium/Low)
        5. Detection patterns to look for
        6. Specific endpoints or functions to test
        7. Step-by-step test execution plan
        8. Mitigation recommendations
        
        Return as JSON array with this structure:
        [
            {{
                "test_name": "Descriptive test name",
                "description": "Detailed description",
                "attack_type": "Specific attack type",
                "payloads": ["payload1", "payload2"],
                "endpoints": ["/api/endpoint1"],
                "risk_level": "Critical|High|Medium|Low",
                "detection_patterns": ["pattern1", "pattern2"],
                "test_steps": ["step1", "step2", "step3"],
                "expected_result": "What to expect if vulnerable",
                "mitigation": "How to fix this vulnerability"
            }}
        ]
        """
        
        response = model.generate_content(prompt)
        
        # Parse and return the test cases
        response_text = response.text.strip()
        
        # Extract JSON array from response
        if response_text.startswith('```json'):
            response_text = response_text[7:]
        if response_text.endswith('```'):
            response_text = response_text[:-3]
        
        response_text = response_text.strip()
        
        # Find JSON array in response
        start_idx = response_text.find('[')
        end_idx = response_text.rfind(']')
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            response_text = response_text[start_idx:end_idx + 1]
        
        try:
            test_cases = json.loads(response_text)
        except json.JSONDecodeError:
            # Fallback test cases
            test_cases = [
                {
                    "test_name": f"Security Test for {request.user_request}",
                    "description": f"Automated test for: {request.user_request}",
                    "attack_type": "general_security_test",
                    "payloads": ["test_payload"],
                    "endpoints": [request.target_url],
                    "risk_level": "Medium",
                    "detection_patterns": ["error", "exception"],
                    "test_steps": ["Send request", "Analyze response", "Check for vulnerabilities"],
                    "expected_result": "No security vulnerabilities detected",
                    "mitigation": "Implement proper security controls"
                }
            ]
        
        return {
            "success": True,
            "test_cases": test_cases,
            "total_tests": len(test_cases)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "test_cases": []
        }
