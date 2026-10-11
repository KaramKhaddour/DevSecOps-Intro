# Lab 9 — two checks the shipped k8s-security.rego does not make.
# Same package as the shipped policy, so conftest evaluates it alongside the
# others under --all-namespaces.
package k8s.security

# DENY: images must be pinned by digest, not a tag.
# The shipped policy only rejects the ":latest" tag; a pinned :v19.0.0 tag still
# floats, because a tag can be re-pushed. A digest cannot.
deny contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q image must be pinned by digest, not a tag", [c.name])
}

# WARN: containers must not add Linux capabilities.
# The shipped policy requires drop:[ALL] but never checks what gets added back.
# Dropping ALL and then adding NET_ADMIN re-grants exactly what was dropped.
warn contains msg if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
	count(c.securityContext.capabilities.add) > 0
	msg := sprintf("container %q must not add capabilities (adds %v)", [c.name, c.securityContext.capabilities.add])
}
