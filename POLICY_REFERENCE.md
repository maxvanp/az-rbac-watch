# Policy Model Reference

Ce document décrit en détail le format du fichier policy model YAML utilisé par Azure Permissions Watch.

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Structure complète](#structure-complète)
- [Header](#header)
  - [version](#version)
  - [tenant_id](#tenant_id)
  - [scope](#scope)
  - [subscriptions](#subscriptions)
  - [management_groups](#management_groups)
  - [exclude_subscriptions / exclude_management_groups](#exclusions)
- [Rules](#rules)
  - [Deux types de rules](#deux-types-de-rules)
  - [Champs d'une rule](#champs-dune-rule)
  - [Match operators](#match-operators)
- [Algorithme de conformité](#algorithme-de-conformité)
- [Scénarios d'usage](#scénarios-dusage)
- [Commandes utiles](#commandes-utiles)

---

## Vue d'ensemble

Le policy model est un fichier YAML qui définit :

1. **Quels scopes scanner** (subscriptions, management groups)
2. **Ce qui est attendu** (baseline rules)
3. **Ce qui est interdit** (governance rules)

L'outil scanne les role assignments RBAC Azure sur les scopes définis, puis les compare aux rules pour détecter les écarts.

---

## Structure complète

```yaml
version: "2.0"                          # Obligatoire
tenant_id: "xxxxxxxx-xxxx-..."          # Obligatoire (UUID)
scope: explicit                          # Optionnel (défaut: explicit)

subscriptions:                           # Liste des subscriptions à scanner
  - id: "11111111-1111-..."
    name: "Production"

management_groups:                       # Liste des management groups à scanner
  - id: "mg-production"
    name: "Production"

exclude_subscriptions:                   # Optionnel (scope: all uniquement)
  - "22222222-2222-..."

exclude_management_groups:               # Optionnel (scope: all uniquement)
  - "mg-sandbox"

rules:                                   # Liste des règles de conformité
  - name: rule-name
    type: governance
    description: "..."
    severity: high
    remediation: "..."
    match:
      principal_type: User
```

---

## Header

### version

**Obligatoire** | Type: `string` | Valeurs: `"2.0"`

Version du format policy model.

```yaml
version: "2.0"
```

### tenant_id

**Obligatoire** | Type: `UUID`

Identifiant du tenant Entra ID (Azure AD).

```yaml
tenant_id: "0197b94a-021f-4794-8c1e-0a4ac9b304a4"
```

Pour le trouver : `az account show --query tenantId -o tsv`

### scope

**Optionnel** | Type: `string` | Valeurs: `"explicit"` (défaut), `"all"`

Détermine comment les scopes à scanner sont définis.

| Mode | Comportement |
|------|-------------|
| `explicit` | Seuls les scopes listés dans `subscriptions` et `management_groups` sont scannés |
| `all` | Auto-discovery de **tous** les scopes accessibles par le credential courant |

```yaml
# Mode explicite (défaut) — vous listez les scopes
scope: explicit
subscriptions:
  - id: "11111111-..."
    name: "Production"

# Mode all — scan automatique de tout ce qui est accessible
scope: all
# subscriptions/management_groups sont ignorés, découverts automatiquement
```

Le mode `all` est utile pour une première découverte ou un scan exhaustif. Le mode `explicit` est recommandé en production pour un contrôle précis.

### subscriptions

**Optionnel** | Type: liste d'objets

Subscriptions Azure à scanner.

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `id` | UUID | oui | ID de la subscription |
| `name` | string | non | Nom d'affichage (pour les rapports) |

```yaml
subscriptions:
  - id: "9025917f-064b-4b0d-abac-73281ef2051b"
    name: "getlink-mis-sbx"
  - id: "11111111-1111-1111-1111-111111111111"
    name: "Production"
```

> **Note** : le scan d'une subscription retourne aussi les role assignments **héritées** des management groups parents. C'est le comportement normal de l'API Azure ARM.

### management_groups

**Optionnel** | Type: liste d'objets

Management groups Azure à scanner.

| Champ | Type | Obligatoire | Description |
|-------|------|-------------|-------------|
| `id` | string | oui | ID du management group |
| `name` | string | non | Nom d'affichage |

```yaml
management_groups:
  - id: "mg-production"
    name: "Production"
  - id: "mg-sandbox"
    name: "Sandbox"
```

### Exclusions

**Optionnel** | Type: liste de strings | **Utilisable uniquement avec `scope: all`**

Permet d'exclure certains scopes lors de l'auto-discovery.

```yaml
scope: all
exclude_subscriptions:
  - "22222222-2222-2222-2222-222222222222"   # Exclure la sandbox
exclude_management_groups:
  - "mg-legacy"                               # Exclure un MG obsolète
```

Les exclusions s'appliquent aussi aux rules ciblant ces scopes (via `scope` ou `scope_prefix`).

> Les exclusions peuvent aussi être passées en CLI : `--exclude-subscription ID --exclude-management-group ID`

---

## Rules

### Deux types de rules

| Type | Rôle | Finding généré | Quand l'utiliser |
|------|------|----------------|------------------|
| `baseline` | Déclare une assignation **attendue** | `DRIFT` (HIGH) pour toute assignation non couverte | Documenter votre architecture de permissions |
| `governance` | Déclare un pattern **interdit** | `GOVERNANCE_VIOLATION` avec la sévérité de la rule | Interdire des pratiques dangereuses |

**Comportement** :

- S'il y a au moins **une baseline rule**, toute assignation qui ne matche aucune baseline = finding `DRIFT`
- S'il n'y a **aucune baseline rule** (governance-only), aucun finding DRIFT n'est généré
- Les governance rules produisent un finding pour **chaque** assignation matchée
- Une assignation peut cumuler les deux : être OUT_OF_BASELINE **et** matcher une governance rule

**Recommendation** :
- Commencez par des governance rules seules (plus facile à mettre en place)
- Ajoutez des baseline rules progressivement via `az-rbac-watch discover`
- Objectif long terme : baseline complète + governance rules = couverture totale

### Champs d'une rule

| Champ | Type | Obligatoire | Défaut | Description |
|-------|------|-------------|--------|-------------|
| `name` | string | **oui** | — | Identifiant unique de la rule (apparaît dans les rapports) |
| `type` | string | non | `"governance"` | `"baseline"` ou `"governance"` |
| `description` | string | non | `""` | Description lisible (affichée dans les findings) |
| `severity` | string | non | `"high"` | Sévérité du finding (voir ci-dessous) |
| `remediation` | string | non | `null` | Conseil de remédiation (affiché dans les rapports) |
| `match` | object | non | `{}` | Conditions de match (voir section suivante) |

**Valeurs de severity** :

| Sévérité | Usage recommandé |
|----------|-----------------|
| `critical` | Risque immédiat de compromission (Owner au scope sub, guest avec Owner) |
| `high` | Violation de gouvernance majeure (user direct, SP direct) |
| `medium` | Écart de pratique (custom roles, naming convention) |
| `low` | Observation à surveiller |
| `info` | Informatif, pas d'action requise |

```yaml
rules:
  - name: no-direct-users
    type: governance
    description: "Les users doivent passer par des groupes"
    severity: high
    remediation: "Ajoutez l'utilisateur à un groupe Entra et assignez le rôle au groupe"
    match:
      principal_type: User
```

### Match operators

Le bloc `match` contient les conditions de filtrage. **Toutes les conditions sont combinées en AND** : une assignation doit satisfaire toutes les conditions pour matcher.

Un `match` vide (`match: {}`) matche **toutes** les assignations.

Toutes les comparaisons sont **case-insensitive**.

#### Filtres sur le scope

| Opérateur | Type | Description |
|-----------|------|-------------|
| `scope` | string | Match exact sur le scope ARM |
| `scope_prefix` | string | Le scope commence par cette valeur |

```yaml
# Match exact : uniquement la subscription Production
match:
  scope: /subscriptions/11111111-1111-1111-1111-111111111111

# Match prefix : la subscription ET tous ses resource groups/resources
match:
  scope_prefix: /subscriptions/11111111-1111-1111-1111-111111111111

# Match prefix : un resource group spécifique et ses resources
match:
  scope_prefix: /subscriptions/11111111-.../resourceGroups/rg-production

# Match prefix : un management group et tous ses enfants
match:
  scope_prefix: /providers/Microsoft.Management/managementGroups/mg-production
```

> **Attention** : `scope_prefix: /subscriptions/` matche **toutes** les subscriptions. Pour cibler une seule subscription et ses sous-scopes, incluez l'ID complet.

> Le trailing slash est automatiquement strippé. `scope_prefix: /subscriptions/xxx/` et `scope_prefix: /subscriptions/xxx` sont équivalents.

#### Filtres sur le rôle

| Opérateur | Type | Description |
|-----------|------|-------------|
| `role` | string | Nom exact du rôle |
| `role_in` | list[string] | Le rôle est dans la liste |
| `role_not_in` | list[string] | Le rôle n'est PAS dans la liste |
| `role_type` | string | `BuiltInRole` ou `CustomRole` |

```yaml
# Rôle exact
match:
  role: Owner

# Le rôle doit être Reader OU Contributor (whitelist)
match:
  role_in:
    - Reader
    - Contributor

# Tous les rôles SAUF Reader et Contributor (blacklist)
match:
  role_not_in:
    - Reader
    - Contributor

# Tous les custom roles
match:
  role_type: CustomRole
```

#### Filtres sur le principal

| Opérateur | Type | Description |
|-----------|------|-------------|
| `principal_type` | string | `User`, `Group`, `ServicePrincipal`, `ForeignGroup`, `Device` |
| `principal_type_in` | list[string] | Le type est dans la liste |
| `principal_id` | string | UUID exact du principal |

```yaml
# Tous les users
match:
  principal_type: User

# Users ET service principals
match:
  principal_type_in:
    - User
    - ServicePrincipal

# Un principal spécifique (pour baseline)
match:
  principal_id: "5dbfb716-7c4e-4825-865d-13b64957b3a5"
```

#### Filtres sur le display name

Ces opérateurs nécessitent l'accès à l'API Graph (permission `Directory.Read.All`). Si la résolution des noms échoue, ces opérateurs retournent **false** (pas de faux positifs).

| Opérateur | Type | Description |
|-----------|------|-------------|
| `principal_name_prefix` | string | Le display name commence par |
| `principal_name_not_prefix` | string | Le display name ne commence PAS par |
| `principal_name_contains` | string | Le display name contient |
| `principal_name_not_contains` | string | Le display name ne contient PAS |

```yaml
# Groupes dont le nom ne commence pas par AZ_
match:
  principal_type: Group
  principal_name_not_prefix: "AZ_"

# Groupes contenant "TEMP"
match:
  principal_type: Group
  principal_name_contains: "TEMP"

# Service principals commençant par "SP_"
match:
  principal_type: ServicePrincipal
  principal_name_prefix: "SP_"
```

#### Combiner les opérateurs (AND)

Toutes les conditions sont combinées en AND. Exemples :

```yaml
# Owner au scope subscription (pas RG ni resource)
match:
  scope_prefix: /subscriptions/
  role: Owner

# Custom roles sur la subscription Production uniquement
match:
  scope_prefix: /subscriptions/11111111-1111-1111-1111-111111111111
  role_type: CustomRole

# Groupes non-AZ_ avec un rôle Owner
match:
  principal_type: Group
  principal_name_not_prefix: "AZ_"
  role: Owner

# Service principals avec Contributor sur un resource group spécifique
match:
  principal_type: ServicePrincipal
  role: Contributor
  scope_prefix: /subscriptions/xxx/resourceGroups/rg-production
```

> **Il n'y a pas de OR.** Pour un OR logique, créez plusieurs rules distinctes.

---

## Algorithme de conformité

L'évaluation se fait en deux passes :

### Passe 1 — Governance rules

Pour chaque assignation scannée, chaque governance rule est évaluée. Si le `match` correspond, un finding `GOVERNANCE_VIOLATION` est créé avec la sévérité de la rule.

Une assignation peut violer **plusieurs** governance rules.

### Passe 2 — Baseline gating

Si au moins une baseline rule existe dans la policy :

- Chaque assignation est testée contre **toutes** les baseline rules
- Si **aucune** baseline rule ne matche → finding `DRIFT` (severity HIGH)
- Si au moins une baseline rule matche → l'assignation est considérée conforme (pour la baseline)

Si aucune baseline rule n'existe, cette passe est ignorée (mode governance-only).

### Résultat

| Situation | Finding |
|-----------|---------|
| L'assignation matche une governance rule | `GOVERNANCE_VIOLATION` (sévérité de la rule) |
| L'assignation ne matche aucune baseline rule | `DRIFT` (HIGH) |
| L'assignation matche une baseline ET une governance | Les deux findings sont créés |
| L'assignation matche une baseline, aucune governance | Conforme — pas de finding |

---

## Scénarios d'usage

### Governance-only (débutant)

Commencez avec uniquement des governance rules. Pas besoin de documenter toutes les assignations existantes.

```yaml
version: "2.0"
tenant_id: "..."
subscriptions:
  - id: "..."
    name: "Production"

rules:
  - name: no-direct-users
    type: governance
    severity: high
    description: "Users must use groups"
    remediation: "Add user to an Entra group"
    match:
      principal_type: User

  - name: groups-naming
    type: governance
    severity: medium
    description: "Groups must start with AZ_"
    remediation: "Rename group with AZ_ prefix"
    match:
      principal_type: Group
      principal_name_not_prefix: "AZ_"
```

### Baseline + governance (avancé)

Utilisez `discover` pour générer les baseline rules, puis ajoutez des governance rules manuellement.

```bash
# 1. Discover existant
az-rbac-watch discover -t <tenant-id> -s <sub-id> -o policy.yaml

# 2. Ajouter des governance rules au fichier généré

# 3. Détecter le drift
az-rbac-watch scan -p policy.yaml -o drift-report.html

# 4. Auditer les guardrails
az-rbac-watch audit -p policy.yaml -o audit-report.html
```

Les baseline rules générées par `discover` ont cette forme :

```yaml
  - name: grp-team-infra-contributor
    type: baseline
    description: "GRP-TEAM-INFRA — Contributor"
    match:
      principal_id: "bbbbbbbb-..."
      role: Contributor
      scope: /subscriptions/.../resourceGroups/rg-infra
```

### Scan exhaustif (scope: all)

Scannez toutes les subscriptions et management groups accessibles, avec des exclusions.

```yaml
version: "2.0"
tenant_id: "..."
scope: all

exclude_subscriptions:
  - "22222222-..."    # sandbox
exclude_management_groups:
  - "mg-legacy"

rules:
  - name: no-direct-users
    type: governance
    severity: high
    match:
      principal_type: User
```

---

## Commandes utiles

```bash
# Valider la syntaxe d'une policy (offline, sans credentials Azure)
az-rbac-watch validate -p policy.yaml

# Découvrir les assignations et générer un draft
az-rbac-watch discover -t <tenant-id> -o draft.yaml
az-rbac-watch discover -t <tenant-id> -s <sub-id> -o draft.yaml

# Détecter le drift (baseline rules)
az-rbac-watch scan -p policy.yaml
az-rbac-watch scan -p policy.yaml -o drift-report.html
az-rbac-watch scan -p policy.yaml -f json -o drift.json

# Auditer les guardrails (governance rules)
az-rbac-watch audit -p policy.yaml
az-rbac-watch audit -p policy.yaml -o audit-report.html
az-rbac-watch audit -p policy.yaml -f json -o audit.json

# Exclure un scope au runtime (sans modifier le YAML)
az-rbac-watch scan -p policy.yaml --exclude-subscription <id>
az-rbac-watch audit -p policy.yaml --exclude-subscription <id>

# Logs détaillés / traceback complète
az-rbac-watch scan -p policy.yaml --verbose --debug
```
