"""
Change Manager - Handles Git operations and PR creation.

This module manages all Git operations including:
- Branch creation
- Committing changes
- Creating pull requests
- Managing PR lifecycle
"""

from __future__ import annotations

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
        self._initialized = False
    
    async def initialize(self) -> None:
        """Initialize Git repository and GitHub client."""
        if self._initialized:
            return
        
        import git
        
        repo_path = Path(self.codebase_config.local_path)
        
        if repo_path.exists():
            self._repo = git.Repo(repo_path)
        else:
            # Clone if doesn't exist
            token = self.codebase_config.auth.get_token()
            url = self.codebase_config.repository_url
            
            if token and "github.com" in url:
                url = url.replace("https://", f"https://{token}@")
            
            repo_path.mkdir(parents=True, exist_ok=True)
            self._repo = git.Repo.clone_from(
                url, repo_path, branch=self.codebase_config.target_branch
            )
        
        # Configure git user
        self._repo.config_writer().set_value(
            "user", "name", self.git_config.user.name
        ).release()
        self._repo.config_writer().set_value(
            "user", "email", self.git_config.user.email
        ).release()
        
        # Initialize GitHub client
        if self.git_config.pull_request.platform == "github":
            await self._init_github()
        
        self._initialized = True
        logger.info("Change manager initialized")
    
    async def _init_github(self) -> None:
        """Initialize GitHub client."""
        from github import Github
        
        token = self.codebase_config.auth.get_token()
        self._github = Github(token)
        
        # Extract owner/repo from URL
        url = self.codebase_config.repository_url
        match = re.search(r'github\.com[:/]([^/]+)/([^/.]+)', url)
        if match:
            self._owner = match.group(1)
            self._repo_name = match.group(2)
    
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
        
        # Generate branch name
        branch_name = self._generate_branch_name(plan)
        
        logger.info(f"Creating PR for plan: {plan.title}", branch=branch_name)
        
        # Create branch
        await self._create_branch(branch_name)
        
        # Apply changes
        files_changed = await self._apply_changes(plan)
        
        # Commit
        commit_sha = await self._commit_changes(plan, files_changed)
        
        # Push
        await self._push_branch(branch_name)
        
        # Create PR
        pr_number, pr_url = await self._create_github_pr(plan, branch_name)
        
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
        }
        
        change_type = type_map.get(plan.change_type, "improvement")
        
        return f"{self.git_config.branch_prefix}{change_type}/{timestamp}-{slug}"
    
    async def _create_branch(self, branch_name: str) -> None:
        """Create a new branch from the target branch."""
        import asyncio
        
        def _create():
            # Ensure we're on the target branch and up to date
            target = self.codebase_config.target_branch
            
            # Fetch latest
            self._repo.remotes.origin.fetch()
            
            # Checkout target branch
            if target in self._repo.heads:
                self._repo.heads[target].checkout()
            else:
                self._repo.git.checkout(f'origin/{target}', b=target)
            
            # Pull latest
            try:
                self._repo.remotes.origin.pull()
            except Exception:
                pass  # May fail if not tracking
            
            # Create new branch
            new_branch = self._repo.create_head(branch_name)
            new_branch.checkout()
        
        await asyncio.to_thread(_create)
        logger.info(f"Created branch: {branch_name}")
    
    async def _apply_changes(self, plan: ImprovementPlan) -> list[str]:
        """Apply code changes from the plan."""
        import asyncio
        
        files_changed = []
        
        for change in plan.changes:
            filepath = Path(self.codebase_config.local_path) / change.file_path
            
            if not filepath.exists():
                logger.warning(f"File not found: {filepath}")
                continue
            
            def _apply(fp: Path, original: str, improved: str) -> bool:
                try:
                    content = fp.read_text()
                    
                    if original and original in content:
                        # Replace the original code with improved
                        new_content = content.replace(original, improved, 1)
                        fp.write_text(new_content)
                        return True
                    else:
                        # Try line-based replacement
                        lines = content.split('\n')
                        start = change.line_start - 1
                        end = change.line_end or start + 1
                        
                        # Replace lines
                        improved_lines = improved.split('\n')
                        lines[start:end] = improved_lines
                        
                        fp.write_text('\n'.join(lines))
                        return True
                
                except Exception as e:
                    logger.error(f"Failed to apply change to {fp}: {e}")
                    return False
            
            success = await asyncio.to_thread(
                _apply, filepath, change.original_code, change.improved_code
            )
            
            if success:
                files_changed.append(change.file_path)
        
        return files_changed
    
    async def _commit_changes(
        self,
        plan: ImprovementPlan,
        files_changed: list[str],
    ) -> str:
        """Commit the changes."""
        import asyncio
        
        def _commit() -> str:
            # Stage files
            for file_path in files_changed:
                self._repo.index.add([file_path])
            
            # Create commit message
            type_prefixes = {
                ChangeType.BUG_FIX: "fix",
                ChangeType.SECURITY_FIX: "security",
                ChangeType.PERFORMANCE: "perf",
                ChangeType.REFACTOR: "refactor",
                ChangeType.CLEANUP: "chore",
                ChangeType.DEPENDENCY_UPDATE: "deps",
            }
            
            prefix = type_prefixes.get(plan.change_type, "improvement")
            message = self.git_config.commit_format.format(
                type=prefix,
                description=plan.title,
            )
            
            # Add body with details
            body = f"\n\n{plan.description}"
            if plan.changes:
                body += "\n\nChanges:"
                for change in plan.changes:
                    body += f"\n- {change.file_path}: {change.description}"
            
            full_message = message + body
            
            # Commit
            commit = self._repo.index.commit(full_message)
            return commit.hexsha
        
        sha = await asyncio.to_thread(_commit)
        logger.info(f"Created commit: {sha[:8]}")
        return sha
    
    async def _push_branch(self, branch_name: str) -> None:
        """Push the branch to remote."""
        import asyncio
        
        def _push():
            self._repo.remotes.origin.push(branch_name, set_upstream=True)
        
        await asyncio.to_thread(_push)
        logger.info(f"Pushed branch: {branch_name}")
    
    async def _create_github_pr(
        self,
        plan: ImprovementPlan,
        branch_name: str,
    ) -> tuple[int, str]:
        """Create a GitHub pull request."""
        import asyncio
        
        def _create() -> tuple[int, str]:
            repo = self._github.get_repo(f"{self._owner}/{self._repo_name}")
            
            title = self._format_title(plan)
            body = self._format_description(plan)
            
            pr = repo.create_pull(
                title=title,
                body=body,
                head=branch_name,
                base=self.codebase_config.target_branch,
            )
            
            # Add labels
            for label in self.git_config.pull_request.labels:
                try:
                    pr.add_to_labels(label)
                except Exception:
                    pass  # Label may not exist
            
            # Request reviewers
            if self.git_config.pull_request.reviewers:
                try:
                    pr.create_review_request(
                        reviewers=self.git_config.pull_request.reviewers
                    )
                except Exception:
                    pass  # Reviewers may not have access
            
            return pr.number, pr.html_url
        
        pr_number, pr_url = await asyncio.to_thread(_create)
        logger.info(f"Created PR #{pr_number}: {pr_url}")
        return pr_number, pr_url
    
    def _format_title(self, plan: ImprovementPlan) -> str:
        """Format PR title."""
        type_names = {
            ChangeType.BUG_FIX: "Bug Fix",
            ChangeType.SECURITY_FIX: "Security",
            ChangeType.PERFORMANCE: "Performance",
            ChangeType.REFACTOR: "Refactor",
            ChangeType.CLEANUP: "Cleanup",
            ChangeType.DEPENDENCY_UPDATE: "Dependencies",
        }
        
        type_name = type_names.get(plan.change_type, "Improvement")
        
        return self.git_config.pull_request.title_format.format(
            type=type_name,
            summary=plan.title[:50],
        )
    
    def _format_description(self, plan: ImprovementPlan) -> str:
        """Format PR description."""
        lines = [
            "## Summary",
            plan.description,
            "",
            "## Changes",
        ]
        
        for change in plan.changes:
            lines.append(f"- **{change.file_path}**: {change.description}")
            if change.reasoning:
                lines.append(f"  - Reasoning: {change.reasoning}")
        
        lines.extend([
            "",
            "---",
            "*This PR was automatically generated by ACIA (Autonomous Code Improvement Agent)*",
        ])
        
        return "\n".join(lines)
    
    async def cleanup_branch(self, branch_name: str) -> None:
        """Delete a branch after PR is merged."""
        import asyncio
        
        def _cleanup():
            # Delete local branch
            if branch_name in self._repo.heads:
                self._repo.delete_head(branch_name, force=True)
            
            # Delete remote branch
            try:
                self._repo.remotes.origin.push(refspec=f":{branch_name}")
            except Exception:
                pass
        
        await asyncio.to_thread(_cleanup)
        logger.info(f"Cleaned up branch: {branch_name}")
