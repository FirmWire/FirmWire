## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import tempfile
import os
from pathlib import PurePath, Path


class WorkspacePath:
    def __init__(self, workspace, path):
        self.workspace = workspace

        if not self.workspace.exists():
            raise ValueError("Workspace has not been created")

        # remove ../ and the like
        path_obj = PurePath(os.path.normpath(path))

        if not path_obj.is_absolute():
            raise ValueError(
                "Workspace paths must be absolute (%s is not)" % (path_obj)
            )

        self.path = path_obj
        # Make all workspace path references relative to the workspace base directory
        self.real_path = Path(self.workspace._base_dir) / self._to_rel_path()

    def _to_rel_path(self):
        # remove the leading /
        return PurePath(*list(self.path.parts[1:]))

    def exists(self):
        return self.real_path.exists()

    def open(self, **kwargs):
        return open(self.real_path, **kwargs)

    def mkdir(self):
        self.real_path.mkdir(exist_ok=True)

    def join(self, part):
        return WorkspacePath(self.workspace, self.path / part)

    def is_dir(self):
        return self.real_path.is_dir()

    def is_file(self):
        return self.real_path.is_file()

    def to_path(self):
        return self.real_path

    def __repr__(self):
        return "<WorkspacePath %s:%s>" % (self.workspace.name, self.path)


class Workspace:
    def __init__(self, base, name=""):
        self._base_dir = Path(base)
        self.name = name

        # user defined workspace names are optional
        # the name is just for cosmetic purposes
        if self.name == "":
            self.name = self._base_dir.name

    def exists(self):
        return self._base_dir.is_dir()

    def create(self):
        self._base_dir.mkdir(exist_ok=True)

    def base_path(self):
        return self._base_dir

    def path(self, path):
        if isinstance(path, WorkspacePath):
            return path

        return WorkspacePath(self, path)

    def __repr__(self):
        return "<Workspace %s>" % (self._base_dir)


class ScratchWorkspace(Workspace):
    def __init__(self, **kwargs):
        # use /tmp or similar by default
        self._scratch_workspace_ref = tempfile.TemporaryDirectory(
            prefix="firmwire_workspace"
        )
        super().__init__(self._scratch_workspace_ref.name, **kwargs)


if __name__ == "__main__":
    proj = Workspace("/tmp/testproj", name="myproj")
    proj.create()
    print(proj)
    path = proj.path("/info")
    print(path)

    print(path.real_path)
    print(path.exists())

    with path.open(mode="w") as fp:
        fp.write("test output\n")
