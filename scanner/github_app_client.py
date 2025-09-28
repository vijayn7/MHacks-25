"""
GitHub App Client - Handles authentication and API calls for GitHub Apps
"""

import os
import jwt
import time
import requests
import json
from typing import Dict, Any, Optional
from datetime import datetime, timedelta

class GitHubAppClient:
    """
    Client for interacting with GitHub Apps API
    """
    
    def __init__(self, app_id: str = None, private_key_path: str = None):
        self.app_id = app_id or os.getenv("GITHUB_APP_ID")
        self.private_key_path = private_key_path or os.getenv("GITHUB_PRIVATE_KEY_PATH")
        
        if not self.app_id:
            raise ValueError("GitHub App ID is required")
        if not self.private_key_path:
            raise ValueError("GitHub App private key path is required")
        
        # Load private key
        with open(self.private_key_path, 'r') as f:
            self.private_key = f.read()
        
        self.base_url = "https://api.github.com"
        self._installation_token = None
        self._token_expires = None
    
    def _generate_jwt_token(self) -> str:
        """
        Generate JWT token for GitHub App authentication
        """
        now = int(time.time())
        payload = {
            "iat": now - 60,  # Issued at (1 minute ago)
            "exp": now + 600,  # Expires in 10 minutes
            "iss": self.app_id  # Issuer (App ID)
        }
        
        token = jwt.encode(payload, self.private_key, algorithm="RS256")
        return token
    
    def _get_installation_token(self, installation_id: str) -> str:
        """
        Get installation access token
        """
        # Check if we have a valid token
        if self._installation_token and self._token_expires and time.time() < self._token_expires:
            return self._installation_token
        
        # Generate new token
        jwt_token = self._generate_jwt_token()
        
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/app/installations/{installation_id}/access_tokens"
        response = requests.post(url, headers=headers)
        
        if response.status_code == 201:
            data = response.json()
            self._installation_token = data["token"]
            self._token_expires = time.time() + 3600  # 1 hour
            return self._installation_token
        else:
            raise Exception(f"Failed to get installation token: {response.text}")
    
    def get_installations(self) -> list:
        """
        Get list of installations for this app
        """
        jwt_token = self._generate_jwt_token()
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/app/installations"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get installations: {response.text}")
    
    def get_repository_tree(self, installation_id: str, owner: str, repo: str, branch: str = "main") -> Dict[str, Any]:
        """
        Get repository tree
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"Failed to get repository tree: {response.text}")
    
    def get_file_content(self, installation_id: str, owner: str, repo: str, file_path: str) -> str:
        """
        Get file content
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/contents/{file_path}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("encoding") == "base64":
                import base64
                return base64.b64decode(data["content"]).decode("utf-8")
            else:
                return data.get("content", "")
        else:
            raise Exception(f"Failed to get file content: {response.text}")
    
    def create_issue(self, installation_id: str, owner: str, repo: str, title: str, body: str, labels: list = None) -> Dict[str, Any]:
        """
        Create an issue
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/issues"
        payload = {
            "title": title,
            "body": body,
            "labels": labels or []
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 201:
            return response.json()
        else:
            raise Exception(f"Failed to create issue: {response.text}")
    
    def create_pr_comment(self, installation_id: str, owner: str, repo: str, pr_number: int, body: str) -> Dict[str, Any]:
        """
        Create a PR comment
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        payload = {"body": body}
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 201:
            return response.json()
        else:
            raise Exception(f"Failed to create PR comment: {response.text}")
    
    def trigger_workflow(self, installation_id: str, owner: str, repo: str, workflow_file: str, inputs: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Trigger a workflow
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_file}/dispatches"
        payload = {
            "ref": "main",
            "inputs": inputs or {}
        }
        
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code == 204:
            return {"status": "triggered"}
        else:
            raise Exception(f"Failed to trigger workflow: {response.text}")
    
    def get_workflow_runs(self, installation_id: str, owner: str, repo: str, workflow_file: str) -> list:
        """
        Get workflow runs
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/workflows/{workflow_file}/runs"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json().get("workflow_runs", [])
        else:
            raise Exception(f"Failed to get workflow runs: {response.text}")
    
    def get_artifacts(self, installation_id: str, owner: str, repo: str, run_id: int) -> list:
        """
        Get artifacts from a workflow run
        """
        token = self._get_installation_token(installation_id)
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        url = f"{self.base_url}/repos/{owner}/{repo}/actions/runs/{run_id}/artifacts"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            return response.json().get("artifacts", [])
        else:
            raise Exception(f"Failed to get artifacts: {response.text}")

# Example usage
def main():
    """
    Example usage of GitHub App Client
    """
    try:
        # Initialize client
        client = GitHubAppClient()
        
        # Get installations
        installations = client.get_installations()
        print(f"Found {len(installations)} installations")
        
        if installations:
            installation = installations[0]
            installation_id = installation["id"]
            owner = installation["account"]["login"]
            
            print(f"Using installation: {owner} (ID: {installation_id})")
            
            # Test repository access
            try:
                tree = client.get_repository_tree(installation_id, owner, "Hello-World")
                print(f"Repository tree has {len(tree.get('tree', []))} items")
            except Exception as e:
                print(f"Repository access test failed: {str(e)}")
        
    except Exception as e:
        print(f"GitHub App Client test failed: {str(e)}")

if __name__ == "__main__":
    main()
