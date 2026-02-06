# Contributing to LinkGuard

Thank you for your interest in contributing to LinkGuard! 🎉

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (Python version, OS, etc.)

### Suggesting Features

Have an idea? Open an issue with:
- Feature description
- Use case / why it's useful
- Proposed implementation (optional)

### Submitting Code

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
   - Follow PEP 8 style guidelines
   - Add type hints to functions
   - Include docstrings
   - Update README if needed
4. **Test your changes**
   ```bash
   python -m py_compile app.py
   ```
5. **Commit with clear messages**
   ```bash
   git commit -m "Add: URL expansion for shortened links"
   ```
6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```
7. **Open a Pull Request**

## Code Style

- Follow **PEP 8** Python style guide
- Use **type hints** for function parameters and return values
- Write **clear docstrings** for functions
- Keep functions **focused and small**
- Add **comments** for complex logic

## Testing

Before submitting:
- Ensure code compiles: `python -m py_compile app.py`
- Test with your own Slack workspace
- Verify no sensitive data is committed

## Questions?

Feel free to open an issue for any questions or clarifications!

---

**Thank you for making LinkGuard better!** 🛡️
