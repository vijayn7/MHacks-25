"""
GitHub OAuth endpoints for localhost development
"""

import os
import requests
import secrets
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import RedirectResponse
from typing import Optional

router = APIRouter()

# Store temporary codes (in production, use a proper database)
temp_codes = {}

@router.get("/github/connect")
async def github_connect():
    """
    Redirect to GitHub OAuth for localhost development
    """
    client_id = os.getenv("GITHUB_CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=500, detail="GitHub Client ID not configured")
    
    # Generate a random state for security
    state = secrets.token_urlsafe(32)
    temp_codes[state] = {"status": "pending"}
    
    # GitHub OAuth URL for localhost
    redirect_uri = "http://localhost:3000/auth/callback"
    scope = "repo,read:user"
    
    auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={client_id}"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&state={state}"
    )
    
    return {"auth_url": auth_url, "state": state}

@router.get("/github/callback")
async def github_callback(
    code: Optional[str] = Query(None),
    state: Optional[str] = Query(None),
    error: Optional[str] = Query(None)
):
    """
    Handle GitHub OAuth callback for localhost
    """
    if error:
        raise HTTPException(status_code=400, detail=f"GitHub OAuth error: {error}")
    
    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")
    
    # Verify state
    if state not in temp_codes:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    try:
        # Exchange code for access token
        client_id = os.getenv("GITHUB_CLIENT_ID")
        client_secret = os.getenv("GITHUB_CLIENT_SECRET")
        
        token_url = "https://github.com/login/oauth/access_token"
        token_data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "state": state
        }
        
        headers = {"Accept": "application/json"}
        response = requests.post(token_url, data=token_data, headers=headers)
        
        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get("access_token")
            
            if access_token:
                # Get user info
                user_response = requests.get(
                    "https://api.github.com/user",
                    headers={"Authorization": f"token {access_token}"}
                )
                
                if user_response.status_code == 200:
                    user_info = user_response.json()
                    
                    # Store token info (in production, store in database)
                    temp_codes[state] = {
                        "status": "success",
                        "access_token": access_token,
                        "user_info": user_info
                    }
                    
                    # Redirect to frontend with success
                    return RedirectResponse(
                        url=f"http://localhost:3000/agentic?github_connected=true&state={state}",
                        status_code=302
                    )
                else:
                    raise HTTPException(status_code=400, detail="Failed to get user info")
            else:
                raise HTTPException(status_code=400, detail="No access token received")
        else:
            raise HTTPException(status_code=400, detail="Failed to exchange code for token")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OAuth callback error: {str(e)}")

@router.get("/github/status")
async def github_status(state: Optional[str] = Query(None)):
    """
    Check GitHub connection status for localhost
    """
    if not state or state not in temp_codes:
        return {
            "connected": False,
            "repositories": [],
            "message": "Not connected to GitHub"
        }
    
    token_info = temp_codes[state]
    if token_info["status"] != "success":
        return {
            "connected": False,
            "repositories": [],
            "message": "GitHub connection failed"
        }
    
    try:
        # Get user repositories
        access_token = token_info["access_token"]
        headers = {"Authorization": f"token {access_token}"}
        
        # Get repositories
        repos_response = requests.get(
            "https://api.github.com/user/repos?type=owner&sort=updated",
            headers=headers
        )
        
        if repos_response.status_code == 200:
            repositories = repos_response.json()
            return {
                "connected": True,
                "repositories": [
                    {
                        "id": repo["id"],
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "private": repo["private"],
                        "html_url": repo["html_url"],
                        "updated_at": repo["updated_at"]
                    }
                    for repo in repositories
                ],
                "user_info": token_info["user_info"]
            }
        else:
            return {
                "connected": True,
                "repositories": [],
                "message": "Failed to fetch repositories"
            }
    
    except Exception as e:
        return {
            "connected": False,
            "repositories": [],
            "message": f"Error checking status: {str(e)}"
        }

@router.get("/github/repositories")
async def get_repositories(state: str = Query(...)):
    """
    Get user repositories for localhost
    """
    if state not in temp_codes or temp_codes[state]["status"] != "success":
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        access_token = temp_codes[state]["access_token"]
        headers = {"Authorization": f"token {access_token}"}
        
        # Get repositories
        repos_response = requests.get(
            "https://api.github.com/user/repos?type=owner&sort=updated&per_page=100",
            headers=headers
        )
        
        if repos_response.status_code == 200:
            repositories = repos_response.json()
            return {
                "repositories": [
                    {
                        "id": repo["id"],
                        "name": repo["name"],
                        "full_name": repo["full_name"],
                        "private": repo["private"],
                        "html_url": repo["html_url"],
                        "description": repo["description"],
                        "language": repo["language"],
                        "updated_at": repo["updated_at"]
                    }
                    for repo in repositories
                ]
            }
        else:
            raise HTTPException(status_code=400, detail="Failed to fetch repositories")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching repositories: {str(e)}")

@router.post("/github/analyze-repo")
async def analyze_repository_localhost(
    repo_owner: str,
    repo_name: str,
    state: str,
    test_request: str = "Test for common vulnerabilities"
):
    """
    Analyze repository for localhost development
    """
    if state not in temp_codes or temp_codes[state]["status"] != "success":
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        access_token = temp_codes[state]["access_token"]
        
        # Use the GitHub code analyzer
        import sys
        from pathlib import Path
        sys.path.append(str(Path(__file__).parent.parent.parent / "scanner"))
        
        from github_code_analyzer import GitHubCodeAnalyzer
        
        # Create analyzer with access token
        analyzer = GitHubCodeAnalyzer()
        analyzer.github_token = access_token
        
        # Analyze repository
        code_files = await analyzer.analyze_repository(repo_owner, repo_name, "main")
        
        # Generate test cases
        test_cases = await analyzer.generate_targeted_tests(code_files, test_request)
        
        return {
            "status": "success",
            "files_analyzed": len(code_files),
            "vulnerabilities_found": sum(len(f.vulnerabilities) for f in code_files),
            "test_cases_generated": len(test_cases),
            "test_cases": test_cases,
            "analysis": [
                {
                    "path": f.path,
                    "language": f.language.value,
                    "functions": f.functions,
                    "vulnerabilities": f.vulnerabilities,
                    "imports": f.imports
                }
                for f in code_files
            ]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/github/trigger-workflow")
async def trigger_workflow_localhost(
    repo_owner: str,
    repo_name: str,
    state: str,
    target_url: str = "https://httpbin.org",
    test_request: str = "Test for common vulnerabilities"
):
    """
    Trigger GitHub workflow for localhost development
    """
    if state not in temp_codes or temp_codes[state]["status"] != "success":
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    try:
        access_token = temp_codes[state]["access_token"]
        headers = {"Authorization": f"token {access_token}"}
        
        # Trigger workflow
        workflow_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/actions/workflows/agentic-security-tests.yml/dispatches"
        
        payload = {
            "ref": "main",
            "inputs": {
                "target_url": target_url,
                "test_request": test_request
            }
        }
        
        response = requests.post(workflow_url, headers=headers, json=payload)
        
        if response.status_code == 204:
            return {
                "status": "success",
                "message": "Workflow triggered successfully",
                "workflow_url": f"https://github.com/{repo_owner}/{repo_name}/actions"
            }
        else:
            raise HTTPException(
                status_code=response.status_code,
                detail=f"Failed to trigger workflow: {response.text}"
            )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Workflow trigger failed: {str(e)}")
