"""
Change Manager - Handles Git operations and PR creation.

This module manages all Git operations including:
- Branch creation
- Committing changes
- Creating pull requests
- Managing PR lifecycle
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from acia.core.config import CodebaseConfig, GitConfig
from acia.core.models import ChangeType, ImprovementPlan, PRStatus, PullRequest


logger = structlog.get_logger(__name__)


class ChangeManager:
    """
    Manages Git operations and PR creation.
    """
    
    def __init__(self, git_config: GitConfig, codebase_config: CodebaseConfig):
        self.git_config = git_config
        self.codebase_config = codebase_config
        self._repo = None
        self._github = None
        self._github_repo = None
        self._initialized = False
        self._owner = None
        self._repo_name = None
    
    async def initialize(self) -> None:
        """Initialize Git repository and GitHub client."""
        if self._initialized:
            return
        
        import git
        
        repo_path = Path(self.codebase_config.local_path)
        
        # Get token for authentication
        token = self.codebase_config.auth.get_token()
        if not token:
            token = os.getenv("GITHUB_TOKEN")
        
        if not token:
            raise ValueError(
                "GitHub token not found. Set GITHUB_TOKEN env var or configure in config.yaml"
            )
        
        if repo_path.exists() and (repo_path / '.git').exists():
            logger.info(f"Using existing repository at {repo_path}")
            self._repo = git.Repo(repo_path)
            # Pull latest changes
            try:
                origin = self._repo.remotes.origin
                origin.pull()
                logger.info("Pulled latest changes")
            except Exception as e:
                logger.warning(f"Could not pull latest changes: {e}")
        else:
            # Clone if doesn't exist
            url = self.codebase_config.repository_url
            
            # Add token to URL for authentication
            if "github.com" in url:
                if url.startswith("https://"):
                    url = url.replace("https://", f"https://{token}@")
                elif url.startswith("git@"):
                    # Convert SSH to HTTPS with token
                    url = re.sub(
                        r'git@github\.com:(.+)/(.+)\.git',
                        f'https://{token}@github.com/\\1/\\2.git',
                        url
                    )
            
            logger.info(f"Cloning repository to {repo_path}")
            repo_path.mkdir(parents=True, exist_ok=True)
            self._repo = git.Repo.clone_from(
                url, repo_path, branch=self.codebase_config.target_branch
            )
        
        # Configure git user
        with self._repo.config_writer() as config:
            config.set_value("user", "name", self.git_config.user.name)
            config.set_value("user", "email", self.git_config.user.email)
        
        # Initialize GitHub client
        if self.git_config.pull_request.platform == "github":
            await self._init_github(token)
        
        self._initialized = True
        logger.info("Change manager initialized", repo_path=str(repo_path))
    
    async def _init_github(self, token: str) -> None:
        """Initialize GitHub client."""
        from github import Github
        
        self._github = Github(token)
        
        # Extract owner/repo from URL
        url = self.codebase_config.repository_url
        
        # Handle various URL formats
        patterns = [
            r'github\.com[:/]([^/]+)/([^/.]+?)(?:\.git)?$',
            r'github\.com[:/]([^/]+)/([^/]+?)/?$',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                self._owner = match.group(1)
                self._repo_name = match.group(2).replace('.git', '')
                break
        
        if not self._owner or not self._repo_name:
            raise ValueError(f"Could not parse GitHub owner/repo from URL: {url}")
        
        logger.info(f"GitHub repo: {self._owner}/{self._repo_name}")
        
        # Get the repository object
        try:
            self._github_repo = self._github.get_repo(f"{self._owner}/{self._repo_name}")
            logger.info(f"Connected to GitHub repo: {self._github_repo.full_name}")
        except Exception as e:
            logger.error(f"Failed to connect to GitHub repo: {e}")
            raise ValueError(
                f"Could not access GitHub repo {self._owner}/{self._repo_name}. "
                f"Check that the repo exists and your token has access. Error: {e}"
            )
    
    async def create_pr(self, plan: ImprovementPlan) -> PullRequest:
        """
        Create a pull request from an improvement plan.
        
        Steps:
        1. Create a new branch
        2. Apply changes
        3. Commit
        4. Push
        5. Create PR
        """
        await self.initialize()
        
        # Validate we have changes to make
        if not plan.changes:
            raise ValueError("No changes in improvement plan")
        
        # Generate branch name
        branch_name = self._generate_branch_name(plan)
        
        logger.info(f"Creating PR for plan: {plan.title}", branch=branch_name)
        print(f"      Creating branch: {branch_name}", flush=True)
        
        # Create branch
        await self._create_branch(branch_name)
        
        # Apply changes
        print(f"      Applying {len(plan.changes)} changes...", flush=True)
        files_changed = await self._apply_changes(plan)
        
        if not files_changed:
            # No files were changed, cleanup and skip
            await self._cleanup_branch(branch_name)
            raise ValueError("No files were successfully modified")
        
        # Commit
        print(f"      Committing {len(files_changed)} files...", flush=True)
        commit_sha = await self._commit_changes(plan, files_changed)
        
        if not commit_sha:
            await self._cleanup_branch(branch_name)
            raise ValueError("Failed to commit changes")
        
        # Push
        print(f"      Pushing to remote...", flush=True)
        await self._push_branch(branch_name)
        
        # Create PR
        print(f"      Creating pull request...", flush=True)
        pr_number, pr_url = await self._create_github_pr(plan, branch_name)
        
        print(f"      ✓ PR #{pr_number} created: {pr_url}", flush=True)
        
        return PullRequest(
            branch_name=branch_name,
            base_branch=self.codebase_config.target_branch,
            commit_sha=commit_sha,
            pr_number=pr_number,
            pr_url=pr_url,
            title=self._format_title(plan),
            description=self._format_description(plan),
            status=PRStatus.OPEN,
            improvement_plan_id=plan.id,
            files_changed=files_changed,
            reviewers=self.git_config.pull_request.reviewers,
        )
    
    def _generate_branch_name(self, plan: ImprovementPlan) -> str:
        """Generate a branch name from the plan."""
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        
        # Slugify the title
        slug = re.sub(r'[^a-z0-9]+', '-', plan.title.lower())
        slug = slug[:30].strip('-')
        
        type_map = {
            ChangeType.BUG_FIX: "fix",
            ChangeType.SECURITY_FIX: "security",
            ChangeType.PERFORMANCE: "perf",
            ChangeType.REFACTOR: "refactor",
            ChangeType.CLEANUP: "cleanup",
            ChangeType.DEPENDENCY_UPDATE: "deps",
            ChangeType.DOCUMENTATION: "docs",
        }
        
        change_type = type_map.get(plan.change_type, "improvement")
        
        return f"{self.git_config.branch_prefix}{change_type}/{timestamp}-{slug}"
    
    async def _create_branch(self, branch_name: str) -> None:
        """Create and checkout a new branch."""
        def _create():
            # Make sure we're on the target branch and up to date
            target = self.codebase_config.target_branch
            
            # Checkout target branch
            if target in self._repo.heads:
                self._repo.heads[target].checkout()
            
            # Try to pull latest
            try:
                self._repo.remotes.origin.pull()
            except Exception:
                pass  # May fail if not tracking
            
            # Delete branch if it already exists
            if branch_name in self._repo.heads:
                self._repo.delete_head(branch_name, force=True)
            
            # Create new branch
            new_branch = self._repo.create_head(branch_name)
            new_branch.checkout()
        
        await asyncio.to_thread(_create)
        logger.info(f"Created branch: {branch_name}")
    
    async def _cleanup_branch(self, branch_name: str) -> None:
        """Cleanup a branch if PR creation fails."""
        def _cleanup():
            try:
                target = self.codebase_config.target_branch
                if target in self._repo.heads:
                    self._repo.heads[target].checkout()
                if branch_name in self._repo.heads:
                    self._repo.delete_head(branch_name, force=True)
            except Exception as e:
                logger.warning(f"Failed to cleanup branch {branch_name}: {e}")
        
        await asyncio.to_thread(_cleanup)
    
    async def _apply_changes(self, plan: ImprovementPlan) -> list[str]:
        """Apply code changes from the plan."""
        files_changed = []
        repo_path = Path(self.codebase_config.local_path)
        
        for change in plan.changes:
            # Handle both absolute and relative paths
            if Path(change.file_path).is_absolute():
                # Convert absolute path to relative to repo
                try:
                    rel_path = Path(change.file_path).relative_to(repo_path)
                    filepath = repo_path / rel_path
                except ValueError:
                    # Path is not relative to repo, try just the filename
                    filepath = repo_path / Path(change.file_path).name
            else:
                filepath = repo_path / change.file_path
            
            if not filepath.exists():
                # Try to find the file in the repo
                filename = Path(change.file_path).name
                found_files = list(repo_path.rglob(filename))
                
                if found_files:
                    filepath = found_files[0]
                    logger.info(f"Found file at: {filepath}")
                else:
                    logger.warning(f"File not found: {change.file_path} (searched in {repo_path})")
                    continue
            
            def _apply(fp: Path, original: str, improved: str) -> bool:
                try:
                    content = fp.read_text()
                    
                    if original and original.strip() and original in content:
                        # Replace the original code with improved
                        new_content = content.replace(original, improved, 1)
                        fp.write_text(new_content)
                        return True
                    elif improved and improved.strip():
                        # If no original or original not found, try line-based replacement
                        lines = content.split('\n')
                        start = max(0, change.line_start - 1)
                        end = min(len(lines), change.line_end if change.line_end else start + 1)
                        
                        # Replace lines
                        improved_lines = improved.split('\n')
                        lines[start:end] = improved_lines
                        
                        fp.write_text('\n'.join(lines))
                        return True
                    else:
                        logger.warning(f"No valid improvement for {fp}")
                        return False
                
                except Exception as e:
                    logger.error(f"Failed to apply change to {fp}: {e}")
                    return False
            
            success = await asyncio.to_thread(
                _apply, filepath, change.original_code, change.improved_code
            )
            
            if success:
                # Store relative path for git
                try:
                    rel_path = str(filepath.relative_to(repo_path))
                except ValueError:
                    rel_path = filepath.name
                files_changed.append(rel_path)
                logger.info(f"Applied change to: {rel_path}")
        
        return files_changed
    
    async def _commit_changes(
        self,
        plan: ImprovementPlan,
        files_changed: list[str],
    ) -> str | None:
        """Commit the changes."""
        
        def _commit() -> str | None:
            try:
                # Stage files
                for file_path in files_changed:
                    self._repo.index.add([file_path])
                
                # Check if there are changes to commit
                if not self._repo.index.diff("HEAD"):
                    logger.warning("No changes to commit")
                    return None
                
                # Create commit message
                commit_msg = self._format_commit_message(plan)
                
                # Commit
                commit = self._repo.index.commit(commit_msg)
                return commit.hexsha
            except Exception as e:
                logger.error(f"Failed to commit: {e}")
                return None
        
        return await asyncio.to_thread(_commit)
    
    async def _push_branch(self, branch_name: str) -> None:
        """Push branch to remote."""
        def _push():
            token = self.codebase_config.auth.get_token()
            
            if not token:
                raise ValueError("GitHub token required to push changes")
            
            origin = self._repo.remotes.origin
            current_url = origin.url
            
            # Build authenticated URL
            if "github.com" in current_url:
                # Remove any existing credentials from URL
                import re
                clean_url = re.sub(r'https://[^@]+@', 'https://', current_url)
                clean_url = re.sub(r'https://', '', clean_url)
                
                # Build new URL with token
                auth_url = f"https://{token}@{clean_url}"
                
                # Temporarily set the URL with token
                origin.set_url(auth_url)
                logger.debug(f"Set push URL with authentication")
            
            try:
                # Push with force to handle any conflicts
                origin.push(branch_name, set_upstream=True)
            finally:
                # Reset URL to not store token in git config
                if "github.com" in current_url:
                    # Keep original URL format (without token for security)
                    original_url = self.codebase_config.repository_url
                    origin.set_url(original_url)
        
        await asyncio.to_thread(_push)
        logger.info(f"Pushed branch: {branch_name}")
    
    async def _create_github_pr(
        self,
        plan: ImprovementPlan,
        branch_name: str,
    ) -> tuple[int, str]:
        """Create a GitHub pull request."""
        
        def _create_pr() -> tuple[int, str]:
            title = self._format_title(plan)
            body = self._format_description(plan)
            
            pr = self._github_repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=self.codebase_config.target_branch,
            )
            
            # Add labels
            if self.git_config.pull_request.labels:
                try:
                    pr.add_to_labels(*self.git_config.pull_request.labels)
                except Exception as e:
                    logger.warning(f"Failed to add labels: {e}")
            
            # Request reviewers
            if self.git_config.pull_request.reviewers:
                try:
                    pr.create_review_request(
                        reviewers=self.git_config.pull_request.reviewers
                    )
                except Exception as e:
                    logger.warning(f"Failed to request reviewers: {e}")
            
            return pr.number, pr.html_url
        
        return await asyncio.to_thread(_create_pr)
    
    def _format_title(self, plan: ImprovementPlan) -> str:
        """Format PR title."""
        type_prefix = {
            ChangeType.BUG_FIX: "fix",
            ChangeType.SECURITY_FIX: "security",
            ChangeType.PERFORMANCE: "perf",
            ChangeType.REFACTOR: "refactor",
            ChangeType.CLEANUP: "cleanup",
            ChangeType.DEPENDENCY_UPDATE: "deps",
            ChangeType.DOCUMENTATION: "docs",
        }
        
        prefix = type_prefix.get(plan.change_type, "improvement")
        
        # Clean up the title
        title = plan.title
        if title.lower().startswith(prefix):
            title = title[len(prefix):].lstrip(": -")
        
        return f"[ACIA] {prefix}: {title}"
    
    def _format_description(self, plan: ImprovementPlan) -> str:
        """Format PR description."""
        lines = [
            "## 🤖 Automated Improvement by ACIA",
            "",
            plan.description,
            "",
            "### Changes",
            "",
        ]
        
        for change in plan.changes:
            lines.append(f"- `{change.file_path}`: {change.description}")
        
        lines.extend([
            "",
            "---",
            "*This PR was automatically generated by [ACIA](https://github.com/raghavared/acia) - Autonomous Code Improvement Agent*",
        ])
        
        return "\n".join(lines)
    
    def _format_commit_message(self, plan: ImprovementPlan) -> str:
        """Format commit message."""
        type_map = {
            ChangeType.BUG_FIX: "fix",
            ChangeType.SECURITY_FIX: "security",
            ChangeType.PERFORMANCE: "perf",
            ChangeType.REFACTOR: "refactor",
            ChangeType.CLEANUP: "cleanup",
            ChangeType.DEPENDENCY_UPDATE: "deps",
            ChangeType.DOCUMENTATION: "docs",
        }
        
        change_type = type_map.get(plan.change_type, "improvement")
        
        return f"[ACIA] {change_type}: {plan.title}\n\n{plan.description}"