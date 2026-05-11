from setuptools import setup, find_packages

setup(
    name="zeroflaw",
    version="1.0.0",
    py_modules=["zeroflaw", "auto_fix"],
    install_requires=[],
    entry_points={
        "console_scripts": [
            "zeroflaw=zeroflaw:main",
        ],
    },
    python_requires=">=3.8",
)