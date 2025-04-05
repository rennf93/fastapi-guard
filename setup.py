import pathlib

from setuptools import find_packages, setup

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()


setup(
    name="fastapi_guard",
    version="1.2.1",
    packages=find_packages(include=["guard", "guard.*"]),
    install_requires=[
        "aiohttp",
        "cachetools",
        "fastapi",
        "ipaddress",
        "maxminddb",
        "redis",
        "requests",
        "uvicorn",
    ],
    extras_require={
        "dev": [
            "httpx",
            "pytest",
            "pytest-asyncio",
            "pytest-mock",
            "ruff",
            "mypy",
        ],
    },
    python_requires=">=3.10,<3.14",
    author="Renzo Franceschini",
    author_email="rennf93@gmail.com",
    description="Security library for FastAPI to control IPs and more.",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/rennf93/fastapi-guard",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Framework :: FastAPI",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    include_package_data=True,
    package_data={
        "fastapi_guard": ["py.typed"],
    },
)
