from setuptools import find_packages, setup

setup(
    packages=find_packages(include=["guard", "guard.*"]),
    include_package_data=True,
    package_data={
        "guard": ["py.typed"],
    },
)
