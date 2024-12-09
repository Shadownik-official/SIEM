from setuptools import setup, find_packages

setup(
    name="siem",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "psutil",
        "distro",
        "stix2",
        "taxii2-client",
        "scikit-learn",
        "numpy",
        "cryptography",
        "pyOpenSSL",
        "prometheus-client",
    ],
    python_requires=">=3.7",
)
