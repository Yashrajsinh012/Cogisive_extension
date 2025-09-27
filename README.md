# Coginivise - VS Code Extension

**Coginivise** is a powerful Visual Studio Code extension designed to detect security vulnerabilities in real-time and provide intelligent secure coding guidance using **RAG (Retrieval-Augmented Generation)** technology.

---

## Features

### 🔒 Vulnerability Detection
- **Hardcoded Secrets:** Identifies exposed API keys, passwords, tokens, and credentials.  
- **Missing Authorization Checks:** Flags functions without proper access control.  
- **SSRF Detection:** Recognizes Server-Side Request Forgery patterns.  
- **Outdated Dependencies:** Checks `package.json` for insecure libraries.  
- **SQL Injection Risks:** Highlights unsafe database queries.  
- **Cross-Site Scripting (XSS):** Detects potential XSS vulnerabilities.  

### 🤖 AI-Powered Coding Assistance
- **RAG-Based Guidance:** Leverages a secure coding knowledge base for context-aware suggestions.  
- **LLM Integration:** Generates improved secure coding prompts via the Groq API.  
- **Offline Support:** Provides local fallback for AI guidance without an internet connection.  
- **Contextual Recommendations:** Evaluates code patterns to provide relevant security tips.  

### ⚡ QuickFix & Automation
- **One-Click Fixes:** Automatically remediate common security issues.  
- **Environment Variable Replacement:** Convert hardcoded secrets to environment variables.  
- **Authorization Templates:** Automatically insert access control checks.  
- **URL Validation:** Add protection against SSRF attacks.  

---

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/coginivise.git
   cd coginivise


## Installation

1. Clone this repository
2. Install dependencies:
   ```bash
   npm install
   ```
3. Compile the extension:
   ```bash
   npm run compile
   ```
4. Press F5 to run the extension in a new Extension Development Host window

## Configuration

### Environment Variables
Create a `.env` file in the project root:
```env
GROQ_API_KEY=your_groq_api_key_here
```

### Secure Coding Knowledge Base
The extension uses two knowledge files:
- `rules/secure_coding_kb.txt` - Comprehensive secure coding guidelines
- `rules/hardcoded-secrets.yml` - Semgrep rules for vulnerability detection

## Usage

### Security Scanning
The extension automatically scans files on save and provides:
- Real-time vulnerability detection
- Inline error highlighting
- QuickFix suggestions
- Detailed security guidance

### Prompt Enhancement
Add comments to your code to get AI-enhanced security prompts:
```javascript
// PROMPT: Write a login function
// ENHANCED_PROMPT: [AI-generated secure implementation guidance]
```

### Supported File Types
- JavaScript (.js)
- TypeScript (.ts)
- JSON (package.json)
- JSX/TSX files

## Security Rules

### Hardcoded Secrets
Detects patterns like:
```javascript
const apiKey = "sk-1234567890abcdef";
const password = 'hardcoded_password';
const config = {
    secret: "api_secret_here"
};
```

### Missing Authorization
Identifies functions without proper auth checks:
```javascript
function getUser(userId) {
    // Missing authorization - will be flagged
    return database.getUser(userId);
}
```

### SSRF Vulnerabilities
Detects user-controlled URLs in HTTP requests:
```javascript
fetch(req.query.url); // Will be flagged
axios.get(req.params.apiUrl); // Will be flagged
```

### Vulnerable Dependencies
Scans package.json for known vulnerabilities:
```json
{
  "dependencies": {
    "lodash": "4.17.5", // CVE-2021-23337
    "axios": "0.21.0"   // CVE-2021-3749
  }
}
```

## Development

### Project Structure
```
src/
├── extension.ts          # Main extension logic
├── test/
│   ├── extension.test.js
│   └── extension.test.ts
rules/
├── secure_coding_kb.txt  # Knowledge base
└── hardcoded-secrets.yml # Semgrep rules
```

### Building
```bash
npm run compile
```

### Testing
```bash
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Security

This extension is designed to help improve code security. However, it should be used as part of a comprehensive security strategy, not as the only security measure.

## Support

For issues and feature requests, please use the GitHub Issues page.

## Changelog

### v1.0.0
- Initial release
- Hardcoded secrets detection
- Missing authorization detection
- SSRF vulnerability detection
- Dependency vulnerability scanning
- AI-powered prompt enhancement
- QuickFix support
=======

