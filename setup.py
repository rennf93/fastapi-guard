from setuptools import setup, find_packages
import pathlib


HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="fastapi_guard",
    version="0.3.3",
    packages=find_packages(include=['guard', 'guard.*']),
    install_requires=[
        "aiohttp",
        "cachetools",
        "fastapi",
        "ipaddress",
        "maxminddb",
        "requests",
        "uvicorn",
    ],
    extras_require={
        "dev": [
            "black",
            "flake8",
            "httpx",
            "pytest",
            "pytest-asyncio",
            "pytest-mock",
        ],
    },
    python_requires=">=3.10",
    author="Renzo Franceschini",
    author_email="rennf93@gmail.com",
    description="A security library for FastAPI to control IPs, log requests, and detect penetration attempts.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/rennf93/fastapi-guard",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: FastAPI",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
    ],
    include_package_data=True,
    package_data={
        "fastapi_guard": ["py.typed"],
    },
)
