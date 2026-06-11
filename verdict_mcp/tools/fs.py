"""Tools 2-3: fs_list, fs_extract (disk images).

Spec ref: spec.md > MCP Server > Tool definitions > #2 fs_list, #3 fs_extract.
Filled in by checklist item 10.

fs_list: list files in a disk image path. Params: image, partition_offset?,
path, recursive? (depth-capped). Wraps Sleuth Kit fls (E01 via libewf, native
on SIFT). No mounting - no root needed.

fs_extract: extract one file from an image into runs/<id>/artifacts/ for
downstream parsing. Params: image, partition_offset?, inode|path. Wraps
icat/tsk_recover.
"""

from __future__ import annotations


def fs_list(image: str, path: str, partition_offset: int | None = None,
            recursive: bool = False) -> dict:
    raise NotImplementedError("Implemented in checklist item 10.")


def fs_extract(image: str, target: str, partition_offset: int | None = None) -> dict:
    raise NotImplementedError("Implemented in checklist item 10.")
