# git-status

Reports the current state of the working tree in this repository.

## What it does

Runs `git status` and summarizes the output for the user: which files
are staged, which are modified but unstaged, and which are untracked.
No files are created, modified, or deleted.

## Usage

Invoke this skill when the user asks what has changed in the repo, or
before committing, to confirm exactly what will be included.

## Output

A short plain-text summary is printed directly to the user's terminal.
Nothing is sent anywhere else, and nothing is written outside of what
`git status` itself already reports.
