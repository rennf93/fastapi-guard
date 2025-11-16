import json
import sys
from datetime import datetime
from pathlib import Path
from typing import TypedDict

import yaml


def update_pyproject_toml(version: str):
    print("Changing pyproject.toml")
    changed_pyproject_toml = False
    with open("pyproject.toml") as f:
        in_section = False
        lines = []
        for line in f:
            lines.append(line)

            if line.startswith("["):
                if "[project]" in line:
                    in_section = True
                else:
                    in_section = False

            if not in_section:
                continue

            if "version = " not in line:
                continue

            previous_version = line.split(" = ")[1].strip().strip('"')
            if previous_version == version:
                print("Version already set on pyproject.toml")
            else:
                print(
                    "Changing version from",
                    previous_version,
                    "to",
                    version,
                    "on pyproject.toml",
                )
                changed_pyproject_toml = True
                lines[-1] = f'version = "{version}"\n'

    if changed_pyproject_toml:
        with open("pyproject.toml", "w") as f:
            f.writelines(lines)
    print("pyproject.toml changed")


class MikeYaml(TypedDict):
    version_selector: bool
    title_switch: bool
    versions_file: str
    versions: list[str]
    aliases: dict[str, str]


class IndentDumper(yaml.Dumper):
    # maintains same indentation style
    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


def update_mike_yml(version: str):
    print("Changing mike.yml")

    with open(".mike.yml") as f:
        data: MikeYaml = yaml.safe_load(f)

        contains_version = version in data["versions"]

        if contains_version:
            print("Version already exists in mike.yml")
            return data["aliases"]["latest"] == version

        has_latest = "latest" in data["versions"]

        if has_latest:
            data["versions"].remove("latest")

        if not contains_version:
            data["versions"].append(version)

        data["versions"] = sorted(data["versions"], reverse=True)

        is_latest = data["versions"][0] == version

        if has_latest:
            data["versions"].append("latest")

        if is_latest:
            data["aliases"]["latest"] = version

    with open(".mike.yml", "w") as f:
        yaml.dump(
            data,
            f,
            IndentDumper,
            sort_keys=False,  # preserve key order
            default_flow_style=False,  # use block style
            width=80,
        )
    print("mike.yml changed")
    return data["aliases"]["latest"] == version


def update_versions_json(version: str) -> bool:
    print("Changing versions.json")
    with open("docs/versions/versions.json") as f:
        data: dict[str, str] = json.load(f)
        if version in data:
            print("Version already exists in versions.json")
            return data["latest"] == version
        data[version] = version
        has_latest = "latest" in data
        if has_latest:
            latest_value = data.pop("latest")
        data = dict(sorted(data.items(), key=lambda x: x[0], reverse=True))
        if has_latest:
            data["latest"] = latest_value

        if list(data.keys())[0] == version:
            data["latest"] = version

    with open("docs/versions/versions.json", "w") as f:
        json.dump(data, f, indent=4)
    print("versions.json changed")
    return data["latest"] == version


def change_index_md(version: str):
    print("Changing index.md")
    with open("docs/index.md") as f:
        lines = []
        for line in f:
            lines.append(line)
            if not line.startswith(
                "docker pull ghcr.io/rennf93/fastapi-guard-example:v"
            ):
                continue
            version_tag = line.split(":v")[1].strip()
            if version_tag == version:
                print("Version already exists in index.md")
                return
            lines[-1] = (
                f"docker pull ghcr.io/rennf93/fastapi-guard-example:v{version}\n"
            )
    with open("docs/index.md", "w") as f:
        f.writelines(lines)
    print("index.md changed")


def update_changelog(file: Path, version: str):
    print(f"Changing {str(file)}")
    with open(file) as f:
        all_versions = []
        for i, line in enumerate(f):
            if line.startswith(f"v{version}"):
                print(f"Version already exists in {str(file)}")
                return

            if line.startswith("v") and len(line.split(" ")) == 2:
                line_version = line.split(" ")[0]
                if line_version.count(".") != 2:
                    print(
                        f"{str(file)}:{i} | Warning: "
                        f"found version with invalid format: {line_version}"
                    )
                    continue
                all_versions.append((i, line_version))

        lower_version_line = None
        for i, v in sorted(all_versions, key=lambda x: x[1], reverse=True):
            if v.removeprefix("v") < version:
                lower_version_line = i
                break

        today = datetime.now().strftime("%Y-%m-%d")
        content = [
            f"v{version} ({today})\n"
            "-------------------\n\n"
            f"TITLE (v{version})\n"
            f"------------\n\n"
            "CONTENT\n\n"
            "___\n\n"
        ]

        f.seek(0)
        lines = []
        for i, line in enumerate(f):
            if i == lower_version_line:
                lines.extend(content)
                lines.append(line)
                print(f"Added content to {str(file)}")
            else:
                lines.append(line)

    with open(file, "w") as f:
        f.writelines(lines)
    print(f"{str(file)} changed")


def main(version: str):
    print("Setting version to", version)
    update_pyproject_toml(version)
    is_latest_mike = update_mike_yml(version)
    is_latest_versions = update_versions_json(version)
    if is_latest_mike != is_latest_versions:
        print("Error: is_latest_mike and is_latest_versions are different")
        sys.exit(1)
    if is_latest_mike:
        change_index_md(version)
    update_changelog(Path("CHANGELOG.md"), version)
    update_changelog(Path("docs/release-notes.md"), version)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python version_helper.py <version>")
        sys.exit(1)
    main(sys.argv[1])
