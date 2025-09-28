"""
GitHub Integration - Triggers security tests on GitHub repositories
"""

import os
import requests
import json
from typing import Dict, Any, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

class GitHubTestRequest(BaseModel):
    repo_owner: str
    repo_name: str
    target_url: str
    test_request: str
    branch: str = "main"

class GitHubTestResponse(BaseModel):
    workflow_id: str
    status: str
    message: str
    workflow_url: str

@router.post("/trigger-github-tests", response_model=GitHubTestResponse)
async def trigger_github_tests(request: GitHubTestRequest):
    """
    Trigger security tests on a GitHub repository
    """
    try:
        # Get GitHub token
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            raise HTTPException(status_code=500, detail="GitHub token not configured")
        
        # Trigger workflow
        workflow_url = f"https://api.github.com/repos/{request.repo_owner}/{request.repo_name}/actions/workflows/agentic-security-tests.yml/dispatches"
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        payload = {
            "ref": request.branch,
            "inputs": {
                "target_url": request.target_url,
                "test_request": request.test_request
            }
        }
        
        response = requests.post(workflow_url, headers=headers, json=payload)
        
        if response.status_code == 204:
            return GitHubTestResponse(
                workflow_id="dispatched",
                status="triggered",
                message="Security tests triggered successfully",
                workflow_url=f"https://github.com/{request.repo_owner}/{request.repo_name}/actions"
            )
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to trigger workflow: {response.text}"
            )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/github-status/{repo_owner}/{repo_name}")
async def get_github_status(repo_owner: str, repo_name: str):
    """
    Get the status of the latest security test run
    """
    try:
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            raise HTTPException(status_code=500, detail="GitHub token not configured")
        
        # Get latest workflow run
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/workflows/agentic-security-tests.yml/runs"
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            runs = response.json().get("workflow_runs", [])
            if runs:
                latest_run = runs[0]
                return {
                    "status": latest_run["status"],
                    "conclusion": latest_run["conclusion"],
                    "created_at": latest_run["created_at"],
                    "updated_at": latest_run["updated_at"],
                    "url": latest_run["html_url"],
                    "artifacts_url": latest_run["artifacts_url"]
                }
            else:
                return {"status": "not_found", "message": "No workflow runs found"}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to get workflow status: {response.text}"
            )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/github-artifacts/{repo_owner}/{repo_name}")
async def get_github_artifacts(repo_owner: str, repo_name: str):
    """
    Get artifacts from the latest security test run
    """
    try:
        github_token = os.getenv("GITHUB_TOKEN")
        if not github_token:
            raise HTTPException(status_code=500, detail="GitHub token not configured")
        
        # Get latest workflow run
        url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/workflows/agentic-security-tests.yml/runs"
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            runs = response.json().get("workflow_runs", [])
            if runs:
                latest_run = runs[0]
                run_id = latest_run["id"]
                
                # Get artifacts
                artifacts_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/runs/{run_id}/artifacts"
                artifacts_response = requests.get(artifacts_url, headers=headers)
                
                if artifacts_response.status_code == 200:
                    artifacts = artifacts_response.json().get("artifacts", [])
                    return {
                        "run_id": run_id,
                        "artifacts": artifacts,
                        "run_url": latest_run["html_url"]
                    }
                else:
                    raise HTTPException(
                        status_code=artifacts_response.status_code,
                        detail=f"Failed to get artifacts: {artifacts_response.text}"
                    )
            else:
                return {"status": "not_found", "message": "No workflow runs found"}
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to get workflow runs: {response.text}"
            )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze-repo")
async def analyze_repository(request: GitHubTestRequest):
    """
    Analyze a GitHub repository without running tests
    """
    try:
        from scanner.github_code_analyzer import GitHubCodeAnalyzer
        
        analyzer = GitHubCodeAnalyzer()
        code_files = await analyzer.analyze_repository(
            request.repo_owner, 
            request.repo_name, 
            request.branch
        )
        
        # Convert to serializable format
        analysis_results = []
        for file in code_files:
            analysis_results.append({
                "path": file.path,
                "language": file.language.value,
                "functions": file.functions,
                "vulnerabilities": file.vulnerabilities,
                "imports": file.imports,
                "size": file.size
            })
        
        return {
            "status": "success",
            "files_analyzed": len(code_files),
            "vulnerabilities_found": sum(len(f.vulnerabilities) for f in code_files),
            "analysis": analysis_results
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/generate-tests-from-repo")
async def generate_tests_from_repo(request: GitHubTestRequest):
    """
    Generate test cases from a GitHub repository
    """
    try:
        from scanner.github_code_analyzer import GitHubCodeAnalyzer
        
        analyzer = GitHubCodeAnalyzer()
        code_files = await analyzer.analyze_repository(
            request.repo_owner, 
            request.repo_name, 
            request.branch
        )
        
        test_cases = await analyzer.generate_targeted_tests(code_files, request.test_request)
        
        return {
            "status": "success",
            "test_cases_generated": len(test_cases),
            "test_cases": test_cases
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
