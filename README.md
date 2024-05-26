# Gatekeeper Operator

Gatekeeper extends the OpenPolicy Agent with:

* An extensible, parameterized policy library
* Native Kubernetes CRDs for instantiating the policy library (aka "constraints")
* Native Kubernetes CRDs for extending the policy library (aka "constraint templates")
* Native Kubernetes CRDs for mutation support
* Audit functionality
* External data support

more details can be found at the [Gatekeeper github](https://github.com/open-policy-agent/gatekeeper) repository.

## Install the Gatekeeper Operator

To install the Gatekeeper Operator we simply need to add a subscription to the openshift-operators namespace.

```
cat <<'EOF' | oc create -f -
apiVersion: operators.coreos.com/v1alpha1
kind: Subscription
metadata:
  labels:
    operators.coreos.com/gatekeeper-operator-product.openshift-operators: ''
  name: gatekeeper-operator-product
  namespace: openshift-operators
spec:
  channel: stable
  installPlanApproval: Automatic
  name: gatekeeper-operator-product
  source: redhat-operators
  sourceNamespace: openshift-marketplace
  startingCSV: gatekeeper-operator-product.v3.14.0
EOF
```

## Use cases


### Prevent Users to modify Administrative NetworkPolicies

In this use-case we want to ensure that NetworkPolicies managed by the Admin Group cannot be modified by Users even if they are Namespace Administrators.

* Create the Constraint Template

    ```
    apiVersion: templates.gatekeeper.sh/v1
    kind: ConstraintTemplate
    metadata:
      name: denynetworkpolicymodifications
    spec:
      crd:
        spec:
          names:
            kind: DenyNetworkPolicyModifications
          validation:
            legacySchema: true
      targets:
        - rego: |
            package DenyNetworkPolicyModifications
            privileged(userInfo, allowedUsers, _) {
              # Allow if the user is in allowedUsers.
              username := object.get(userInfo, "username", "")
              allowedUsers[_] == username
            } 
            privileged(userInfo, _, allowedGroups) {
              # Allow if the user's groups intersect allowedGroups.
              userGroups := object.get(userInfo, "groups", [])
              groups := {g | g := userGroups[_]}
              allowed := {g | g := allowedGroups[_]}
              intersection := groups & allowed
              count(intersection) > 0
            }
            violation[{"msg": msg}] {
              params := object.get(input, "parameters", {})
              policyName := input.review.object.metadata.name
              input.review.kind.kind == "NetworkPolicy"
              allowedUsers := object.get(params[policyName], "allowedUsers", [])
              allowedGroups := object.get(params[policyName], "allowedGroups", [])
              not privileged(input.review.userInfo, allowedUsers, allowedGroups)
              msg := sprintf("User %v is not allowed to create/modify NetworkPolicy %v", 
                             [input.review.userInfo.username, policyName])
            }
          target: admission.k8s.gatekeeper.sh
    ``` 

* Create the Constraint to enforce the policy 

    ```
    apiVersion: constraints.gatekeeper.sh/v1beta1
    kind: DenyNetworkPolicyModifications
    metadata:
      name: denynetworkpolicymodifications
    spec:
      enforcementAction: deny
      match:
        kinds:
          - apiGroups:
              - networking.k8s.io
            kinds:
              - NetworkPolicy
      parameters:
        global-policy:
          allowedGroups: ["network-policy-admins"]
          allowedUsers: []
    ```

    The Constraint configures that only Users in the Group `network-policy-admins` can create/modify/delete the NetworkPolicy call `global-policy` 

* Verify that the ConstraintTemplate as well as the Constraint are in place

    ```
    $ oc get constraints
    NAME                             ENFORCEMENT-ACTION   TOTAL-VIOLATIONS
    denynetworkpolicymodifications   deny     
    ``` 

    You would see an error like below if Gatekeeper hasn't finished adding the Constraint and Template accordingly.

    ```
    error: the server doesn't have a resource type "denyrouteperdomainpolicy"
    ```

* Verify that a User not in the Group `network-policy-admins` cannot create/modify/delete the NetworkPolicy called `global-policy` but can add it's custom policy.

    ```
    # create a namespace for testing 
    oc create namespace gktest

    # create two NetworkPolicies
    cat <<'EOF' | oc -n gktest create -f - 
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: global-policy
    spec:
      podSelector: {}
      policyTypes: []
    ---
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: users-policy
    spec:
      podSelector: {}
      policyTypes: []
    ---
    EOF

    # Expected output: 
    # first NetworkPolicy is rejected 
    # second NetworkPolicy is accepted

    networkpolicy.networking.k8s.io/users-policy created
    Error from server (Forbidden): error when creating "STDIN": admission webhook "validation.gatekeeper.sh" denied the request: [denynetworkpolicymodifications] User milang is not allowed to create/modify NetworkPolicy global-policy
    ```


### Prevent Users to create Routes in not granted domains

In this use-case we want to ensure that Users cannot create Routes in domains that are not granted accordingly. 

* Create the Constraint Template

    ```
    cat <<'EOF' | oc create -f - 
    apiVersion: templates.gatekeeper.sh/v1
    kind: ConstraintTemplate
    metadata:
      name: denyrouteperdomainpolicy
    spec:
      crd:
        spec:
          names:
            kind: DenyRoutePerDomainPolicy
          validation:
            legacySchema: true
      targets:
        - rego: |
            package DenyRoutePerDomainPolicy
            privileged(userInfo, allowedUsers, _) {
              # Allow if the user is in allowedUsers.
              username := object.get(userInfo, "username", "")
              allowedUsers[_] == username
            } 
            privileged(userInfo, _, allowedGroups) {
              # Allow if the user's groups intersect allowedGroups.
              userGroups := object.get(userInfo, "groups", [])
              groups := {g | g := userGroups[_]}
              allowed := {g | g := allowedGroups[_]}
              intersection := groups & allowed
              count(intersection) > 0
            }
            violation[{"msg": msg}] {
              params := object.get(input, "parameters", {})
              routeName := input.review.object.spec.host
              idx := indexof(routeName, ".")
              domain := substring(routeName, idx + 1, count(routeName))
              input.review.kind.kind == "Route"
              not params[domain]
              msg := sprintf("User %v is not allowed to create/modify Route %v in domain %v",
                             [input.review.userInfo.username, routeName, domain])
            }
            violation[{"msg": msg}] {
              params := object.get(input, "parameters", {})
              routeName := input.review.object.spec.host
              idx := indexof(routeName, ".")
              domain := substring(routeName, idx + 1, count(routeName))
              allowedUsers := object.get(params[domain], "allowedUsers", [])
              allowedGroups := object.get(params[domain], "allowedGroups", [])
              input.review.kind.kind == "Route"
              not privileged(input.review.userInfo, allowedUsers, allowedGroups)
              msg := sprintf("User %v is not allowed to create/modify Route %v in domain %v %v %v", 
                             [input.review.userInfo.username, routeName, domain, allowedUsers, allowedGroups])
            }
          target: admission.k8s.gatekeeper.sh
    EOF
    ``` 

* Create the Constraint to enforce the policy

    The Constraint accepts Parameters in form of

    ```
    parameters:
      "domain":
        allowedGroups: []
        allowedUsers: []
    ```

    ```
    cat <<'EOF' | oc create -f - 
    apiVersion: constraints.gatekeeper.sh/v1beta1
    kind: DenyRoutePerDomainPolicy
    metadata:
      name: denyrouterperdomainpolicy
    spec:
      enforcementAction: deny
      match:
        kinds:
          - apiGroups:
              - route.openshift.io
            kinds:
              - Route
      parameters:
        "example.com":
          allowedGroups: ["example.com"]
          allowedUsers: ["admin"]
        "somedomain.com":
          allowedGroups: ["somedomain.com"]
          allowedUsers: ["admin"]
    EOF
    ```

    The given example Constraint ensures:
    * Only Users in the Group `example.com` can create Routes for that example.com domain
    * User `admin` can create Routes even if not in Group `example.com` 
    * Only Users in the Group `somdomain.com` can create Route for the somdomain.com domain
    * User `admin` can create Routes even if not in Group `somedomain.com` 
    * not configured domains are always rejected

* Verify that a User not in the Group `example.com` cannot create/modify/delete Routes with `spec.host` in that domain

    ``` 
    cat <<'EOF' | oc -n gktest create -f -
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test1
    spec:
      host: host.example.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test2
    spec:
      host: host.subdomain.example.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test3
    spec:
      host: host.somedomain.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test4
    spec:
      host: host.xxx.xx
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    EOF

    # expected response all Routes are rejected since we do not have a User or Group matching
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.example.com in domain example.com ["admin"] ["what.example.com"]
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.subdomain.example.com in domain subdomain.example.com
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.somedomain.com in domain somedomain.com ["admin"] ["else.somedomain.com"]
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.xxx.xx in domain xxx.xx
    ```

* Create or update the Groups `example.com` `somedomain.com` 

    ```
    cat <<'EOF' | oc apply -f - 
    apiVersion: user.openshift.io/v1
    kind: Group
    metadata:
      name: example.com
    users:
      - milang
      - admin
    ---
    apiVersion: user.openshift.io/v1
    kind: Group
    metadata:
      name: somedomain.com
    users:
      - milang
    EOF
    ``` 

* Reapply the Routes again

    ```
    cat <<'EOF' | oc -n gktest create -f -
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test1
    spec:
      host: host.example.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test2
    spec:
      host: host.subdomain.example.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---
    apiVersion: route.openshift.io/v1
    kind: Route
    metadata:
      name: test3
    spec:
      host: host.somedomain.com
      port:
        targetPort: http-8080
      to:
        kind: Service
        name: mockbin
        weight: 100
      wildcardPolicy: None
    ---     
    apiVersion: route.openshift.io/v1
    kind: Route 
    metadata:
      name: test4
    spec:     
      host: host.xxx.xx
      port:   
        targetPort: http-8080
      to:   
        kind: Service 
        name: mockbin
        weight: 100
      wildcardPolicy: None
    EOF

    # expected output 
    route.route.openshift.io/test1 created
    route.route.openshift.io/test3 created
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.subdomain.example.com in domain subdomain.example.com
    Error from server (Forbidden): error when creating "routes.yml": admission webhook "validation.gatekeeper.sh" denied the request: [denyrouterperdomainpolicy] User milang is not allowed to create/modify Route host.xxx.xx in domain xxx.xx
    ``` 
