"""Inspect the packaged Runtime vocabulary and its normalized Zenith imports offline."""

from __future__ import annotations

import argparse
import hashlib
from importlib.resources import files
import json

from jsonschema import Draft202012Validator

SCHEMA_VERSION = "process-runtime.ontology-sources.v1"
ROOT_CLASS = "owl:Thing"
PREFIXES = {
    "zn": "https://zenith-research.ca/ontology/terms/",
    "owl": "http://www.w3.org/2002/07/owl#",
    "rdfs": "http://www.w3.org/2000/01/rdf-schema#",
}


def _read(root, path):
    return json.loads(root.joinpath(path).read_bytes())


def _import_closure(documents, entry):
    visiting, complete = set(), set()

    def visit(iri):
        if iri in visiting:
            raise ValueError("Cyclic ontology import")
        if iri in complete:
            return
        if iri not in documents:
            raise ValueError("Ontology import is absent from the packaged closure")
        visiting.add(iri)
        header = documents[iri]["@graph"][0]
        for dependency in header.get("imports", []):
            visit(dependency)
        visiting.remove(iri)
        complete.add(iri)

    visit(entry)
    return complete


def _inheritance_paths(term, parents, visiting=()):
    if term == ROOT_CLASS:
        return [[ROOT_CLASS]]
    if term in visiting:
        raise ValueError("Cyclic class inheritance")
    if term not in parents:
        raise ValueError("Class parent is absent from the imported vocabulary")
    paths = []
    for parent in parents[term]:
        for path in _inheritance_paths(parent, parents, (*visiting, term)):
            paths.append([*path, term])
    return paths


def _load():
    root = files("process_runtime").joinpath("ontology_resources")
    manifest = _read(root, "manifest.json")
    if manifest["schemaVersion"] != "process-runtime.ontology-module.v1":
        raise ValueError("Unsupported Runtime ontology manifest")
    for entry in manifest["files"]:
        contents = root.joinpath(entry["path"]).read_bytes()
        if (len(contents) != entry["bytes"]
                or hashlib.sha256(contents).hexdigest() != entry["sha256"]):
            raise ValueError("Runtime ontology file integrity mismatch")

    dependency = manifest["adoptedZenith"]
    upstream = root.joinpath("zenith-v0.1.0")
    upstream_bytes = upstream.joinpath("manifest.json").read_bytes()
    if hashlib.sha256(upstream_bytes).hexdigest() != dependency["manifestSha256"]:
        raise ValueError("Pinned Zenith manifest integrity mismatch")
    upstream_manifest = json.loads(upstream_bytes)
    records = "".join(f"{entry['sha256']}  {entry['path']}\n"
                      for entry in upstream_manifest["files"])
    if hashlib.sha256(records.encode()).hexdigest() != dependency["bundleDigest"]:
        raise ValueError("Pinned Zenith bundle digest mismatch")
    upstream_files = {entry["path"]: entry for entry in upstream_manifest["files"]}
    for path in dependency["vendoredFiles"]:
        if hashlib.sha256(upstream.joinpath(path).read_bytes()).hexdigest() != upstream_files[path]["sha256"]:
            raise ValueError("Pinned Zenith file integrity mismatch")

    documents = {}
    for path in manifest["ontologyDocuments"]:
        document = _read(root, path)
        if not isinstance(document["@context"], dict):
            raise ValueError("Packaged ontologies require inline contexts")
        context = document["@context"]
        for prefix, iri in PREFIXES.items():
            if context.get(prefix) != iri:
                raise ValueError("Vocabulary context changes a shared namespace")
        for name, meaning in {"imports": "owl:imports", "subClassOf": "rdfs:subClassOf",
                              "versionIRI": "owl:versionIRI"}.items():
            if context.get(name) != {"@id": meaning, "@type": "@id"}:
                raise ValueError("Vocabulary context changes import or inheritance meaning")
        header = document["@graph"][0]
        if header["@type"] != "owl:Ontology" or header["versionIRI"] in documents:
            raise ValueError("Missing or duplicate ontology identity")
        documents[header["versionIRI"]] = document
    closure = _import_closure(documents, manifest["versionIri"])
    if closure != set(documents):
        raise ValueError("Unreachable packaged ontology document")
    own = documents[manifest["versionIri"]]
    if (own["@graph"][0]["@id"] != manifest["ontologyId"]
            or own["@graph"][0]["versionInfo"] != manifest["version"]
            or own["@context"]["runtime"] != manifest["namespace"]):
        raise ValueError("Runtime vocabulary identity mismatch")

    parents = {}
    for document in documents.values():
        for node in document["@graph"]:
            if node.get("@type") != "owl:Class":
                continue
            name = node["@id"]
            if name in parents:
                raise ValueError("Duplicate class definition in ontology imports")
            declared = node.get("subClassOf", ROOT_CLASS)
            parents[name] = declared if isinstance(declared, list) else [declared]
    declared_parents = {
        node["@id"]: node["subClassOf"] for node in own["@graph"]
        if node.get("@type") == "owl:Class"
    }
    if (declared_parents != manifest["parents"]
            or any(not term.startswith("runtime:") for term in declared_parents)):
        raise ValueError("Runtime class inventory differs from its manifest")
    for term in parents:
        _inheritance_paths(term, parents)
    domain = _read(root, "domain.json")
    Draft202012Validator(_read(upstream, "schemas/domain.schema.json")).validate(domain)
    if (domain["sourceModuleRef"] != manifest["versionIri"]
            or domain["vocabularyRef"] != manifest["ontologyId"]):
        raise ValueError("Runtime domain references a different module or vocabulary")
    return root, manifest, documents, parents, domain


def ontology_document():
    """Return the verified Runtime-owned JSON-LD module."""
    _, manifest, documents, _, _ = _load()
    return documents[manifest["versionIri"]]


def schema_mappings():
    """Return application record, reference and collection dispositions."""
    root, _, _, _, _ = _load()
    return _read(root, "mappings.json")


def ontology_sources():
    """Verify local assets and describe all Runtime inheritance paths."""
    root, manifest, documents, parents, domain = _load()
    return {
        "schemaVersion": SCHEMA_VERSION,
        "extension": {
            "ontologyId": manifest["ontologyId"], "version": manifest["version"],
            "versionIri": manifest["versionIri"], "namespace": manifest["namespace"],
            "status": manifest["status"], "ontologyPath": str(root.joinpath("ontology.jsonld")),
            "manifestPath": str(root.joinpath("manifest.json")),
        },
        "adoptedZenith": manifest["adoptedZenith"],
        "closureVerified": True,
        "importClosure": sorted(documents),
        "classes": [
            {"id": term, "parents": parents[term],
             "inheritancePaths": _inheritance_paths(term, parents)}
            for term in sorted(manifest["parents"])
        ],
        "sharedReuse": {
            term: {"class": target, "inheritancePaths": _inheritance_paths(target, parents)}
            for term, target in {"Artifact": "zn:Artifact", "RuntimeInbox": "zn:Inbox",
                                 "RuntimeOutbox": "zn:Outbox"}.items()
        },
        "domain": domain,
        "mappingsPath": str(root.joinpath("mappings.json")),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=["sources-v1"], default="sources-v1")
    parser.parse_args()
    print(json.dumps(ontology_sources(), sort_keys=True))


if __name__ == "__main__":
    main()
