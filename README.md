# Bastet Wisdom

[![MkDocs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://www.mkdocs.org/)
[![Material](https://img.shields.io/badge/theme-material-purple.svg)](https://squidfunk.github.io/mkdocs-material/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Bastet Wisdom** is a comprehensive knowledge base for security testing and bug bounty hunting methodologies. Part of the [Bastet.ai](https://bastet.ai) security tools suite, this wiki provides systematic approaches, best practices, and detailed documentation for security researchers.

## 🎯 Overview

This MkDocs-powered wiki contains:

- **Methodologies**: Step-by-step security testing approaches
- **Tools**: Documentation for the Bastet security tool suite
- **Checklists**: Comprehensive testing guidelines
- **Payloads**: Curated collections of attack vectors
- **Best Practices**: Professional standards and ethics

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Git

### Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/bastet-ai/bastet-wisdom.git
   cd bastet-wisdom
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Serve the documentation locally**:
   ```bash
   mkdocs serve
   ```

5. **Open your browser** and navigate to `http://127.0.0.1:8000`

### Building for Production

```bash
# Build static site
mkdocs build

# Deploy to GitHub Pages (if configured)
mkdocs gh-deploy
```

## 📁 Project Structure

```
bastet-wisdom/
├── docs/                           # Documentation source files
│   ├── index.md                   # Homepage
│   ├── methodology/               # Testing methodologies
│   │   ├── overview.md
│   │   ├── reconnaissance.md
│   │   ├── vulnerability-assessment.md
│   │   ├── exploitation.md
│   │   └── post-exploitation.md
│   ├── tools/                     # Tool documentation
│   │   ├── bastet-suite.md
│   │   ├── web-application.md
│   │   ├── network.md
│   │   ├── mobile.md
│   │   └── cloud.md
│   ├── checklists/                # Testing checklists
│   │   ├── web-applications.md
│   │   ├── apis.md
│   │   ├── mobile-apps.md
│   │   └── infrastructure.md
│   ├── payloads/                  # Attack payloads
│   │   ├── xss.md
│   │   ├── sql-injection.md
│   │   ├── command-injection.md
│   │   └── file-upload.md
│   └── best-practices/            # Best practices
│       ├── reporting.md
│       ├── documentation.md
│       ├── communication.md
│       └── legal-ethics.md
├── mkdocs.yml                     # MkDocs configuration
├── requirements.txt               # Python dependencies
├── venv/                          # Virtual environment (local)
└── README.md                      # This file
```

## 🛠️ Technology Stack

- **[MkDocs](https://www.mkdocs.org/)**: Static site generator
- **[Material for MkDocs](https://squidfunk.github.io/mkdocs-material/)**: Modern theme
- **[Python Markdown Extensions](https://python-markdown.github.io/extensions/)**: Enhanced Markdown support
- **[Mermaid](https://mermaid-js.github.io/)**: Diagram and flowchart support

### Key Plugins

- `mkdocs-material`: Beautiful, responsive Material Design theme
- `mkdocs-awesome-pages-plugin`: Flexible page organization
- `mkdocs-git-revision-date-localized-plugin`: Auto-generated last modified dates
- `mkdocs-minify-plugin`: HTML/CSS/JS minification
- `mkdocs-mermaid2-plugin`: Diagram support
- `pymdown-extensions`: Advanced Markdown features

## 📝 Contributing

We welcome contributions! Here's how to get started:

### Content Contributions

1. **Fork** the repository
2. **Create** a new branch for your changes
3. **Add or modify** documentation files
4. **Test** your changes locally with `mkdocs serve`
5. **Submit** a pull request

### Writing Guidelines

- Use clear, concise language
- Include code examples where applicable
- Add diagrams for complex concepts using Mermaid
- Follow the existing structure and formatting
- Test all links and examples

### File Naming Conventions

- Use lowercase with hyphens: `web-applications.md`
- Be descriptive: `sql-injection-payloads.md`
- Group related content in subdirectories

## 🔧 Configuration

### MkDocs Configuration

The site is configured via `mkdocs.yml`. Key sections:

- **Navigation**: Define the site structure
- **Theme**: Material theme with custom colors and features
- **Plugins**: Enhanced functionality
- **Markdown Extensions**: Advanced formatting support

### Customization

To customize the appearance:

1. **Colors**: Modify the `palette` section in `mkdocs.yml`
2. **Logo**: Add a logo file and reference it in the theme config
3. **Favicon**: Place `favicon.ico` in the `docs/` directory
4. **Custom CSS**: Add styles in `docs/stylesheets/extra.css`

## 📚 Documentation

- **[MkDocs Documentation](https://www.mkdocs.org/)**
- **[Material for MkDocs Guide](https://squidfunk.github.io/mkdocs-material/)**
- **[Markdown Guide](https://www.markdownguide.org/)**
- **[Mermaid Documentation](https://mermaid-js.github.io/mermaid/)**

## 🐛 Issues and Support

- **Bug Reports**: [GitHub Issues](https://github.com/bastet-ai/bastet-wisdom/issues)
- **Feature Requests**: [GitHub Discussions](https://github.com/bastet-ai/bastet-wisdom/discussions)
- **Community**: [Bastet.ai Community Forum](https://community.bastet.ai)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Acknowledgments

- The security research community for sharing knowledge
- Contributors who help improve this documentation
- The MkDocs and Material theme developers

## 🔗 Related Projects

- **[Bastet Suite](https://github.com/bastet-ai/bastet-suite)**: Security testing tools
- **[Bastet Scanner](https://github.com/bastet-ai/bastet-scanner)**: Vulnerability scanner
- **[Bastet Recon](https://github.com/bastet-ai/bastet-recon)**: Reconnaissance toolkit

---

**Bastet Wisdom** - *Empowering security researchers with knowledge and methodology*

[🏠 Home](https://bastet.ai) | [📖 Documentation](https://wisdom.bastet.ai) | [🛠️ Tools](https://github.com/bastet-ai) | [💬 Community](https://community.bastet.ai)
