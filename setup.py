from setuptools import setup, find_packages
import pathlib


HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="fastapi_guard",
    version="0.2.0",
    packages=find_packages(),
    install_requires=[
        "aiohttp",
        "cachetools",
        "fastapi",
        "ipaddress",
        "IP2Location",
        "requests",
        "uvicorn",
    ],
    extras_require={
        "dev": [
            "httpx",
            "pytest",
            "pytest-asyncio",
            "pytest-mock",
        ],
    },
    author="Renzo Franceschini",
    author_email="rennf93@gmail.com",
    description="A security library for FastAPI to control IPs, log requests, and detect penetration attempts.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/rennf93/fastapi_guard",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.10",
    include_package_data=True,
)
