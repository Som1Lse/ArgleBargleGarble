from distutils.core import setup
from distutils.extension import Extension

setup(
    name='pyaesni',
    ext_modules=[
        Extension(
            name='pyaesni',
            sources=[
                'pyaesnimodule.cpp',
            ],
        ),
    ],
)
