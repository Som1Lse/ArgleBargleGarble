#!/usr/bin/env python3

from setuptools import setup, Extension

setup(
    name="pyaesni",
    ext_modules=[
        Extension(
            name="pyaesni",
            sources=[
                "pyaesnimodule.cpp",
            ],
        ),
    ],
)
