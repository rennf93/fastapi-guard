from setuptools import setup, find_packages

setup(
    name="fastapi_guard",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "uvicorn",
    ],
    author="Renzo Franceschini",
    author_email="rennf93@gmail.com",
    description="A security library for FastAPI to control IPs, log requests, and detect penetration attempts.",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/rennf93/fastapi_guard",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.10',
)