#!/usr/bin/env python3
from setuptools import Extension, setup

ext_modules = [
    Extension(
        name="_spectramesh_ouidb",
        sources=["_spectramesh_ouidb.c", "oui_db.c"],
        depends=["oui_db.h"],
        extra_compile_args=["-O2", "-Wall", "-Wextra"],
    )
]

setup(
    name="spectramesh_ouidb",
    version="0.1.0",
    description="Python bindings for SpectraMesh SOUI OUI database (oui_db.c / oui_db_cli)",
    py_modules=["spectramesh_ouidb"],
    ext_modules=ext_modules,
    entry_points={
        "console_scripts": [
            "spectramesh_ouidb = spectramesh_ouidb:main",
            "spectramesh-ouidb = spectramesh_ouidb:main",
        ],
    },
    python_requires=">=3.8",
)
