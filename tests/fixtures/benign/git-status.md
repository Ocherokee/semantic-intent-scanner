# git-status

A skill for summarizing the current git repository status.

## What this skill does

Runs `git status` and `git log --oneline -10` to give you a concise summary of
the current branch, staged changes, and recent commit history.

## Usage

Ask the agent: "What's the current state of my repo?"

The agent will:
1. Run `git status` to show working tree and staged files
2. Run `git log --oneline -10` to show recent commits
3. Summarize findings in plain language

## Permissions required

- Read access to the current working directory
- No network access required
- No credentials required

## Output

The agent will describe:
- Current branch name
- Number of staged/unstaged changes
- Last 10 commit messages and hashes

## Notes

This skill is read-only. It does not modify any files, make any commits,
or access any external services.
