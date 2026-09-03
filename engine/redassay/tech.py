"""Framework detection.

`languages.py` answers "what is this file written in". This answers the more
useful question: "what is this application built with". They are different
questions with different consequences - `.py` tells you almost nothing, but
"Django" tells you where the routes are, what the auth decorator is called, and
which three mistakes that community makes most often.

Detection is sentinel-based: a marker file, or a dependency in a manifest. No
parsing, no heuristics over source. A framework is either declared or it is not,
and guessing produces guidance aimed at the wrong stack - which is worse than no
guidance at all.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set

from .walker import SourceFile


@dataclass(frozen=True)
class Tech:
    """A framework or platform, and what it implies for a reviewer."""

    tag: str
    label: str
    language: str
    #: Where its request handlers live, for the entry-point inventory.
    entry_hint: str = ""
    #: Short, specific risk notes. Facts about the framework, not a tutorial -
    #: the reader already knows the framework, they need the sharp edges.
    notes: Sequence[str] = ()


#: Dependency name -> tag. Matched against manifest contents.
DEPENDENCY_MARKERS: Dict[str, Sequence[str]] = {
    # JavaScript / TypeScript
    "next": ("nextjs",),
    "react": ("react",),
    "react-dom": ("react",),
    "express": ("express",),
    "fastify": ("fastify",),
    "koa": ("koa",),
    "hono": ("hono",),
    "@nestjs/core": ("nestjs",),
    "@sveltejs/kit": ("sveltekit",),
    "nuxt": ("nuxt",),
    "@remix-run/node": ("remix",),
    "socket.io": ("socketio",),
    "graphql": ("graphql",),
    "bullmq": ("bullmq",),
    "prisma": ("prisma",),
    "@prisma/client": ("prisma",),
    "mongoose": ("mongoose",),
    "sequelize": ("sequelize",),
    "knex": ("knex",),
    "jsonwebtoken": ("jwt",),
    "passport": ("passport",),
    # Python
    "django": ("django",),
    "djangorestframework": ("django", "drf"),
    "flask": ("flask",),
    "fastapi": ("fastapi",),
    "starlette": ("starlette",),
    "aiohttp": ("aiohttp",),
    "tornado": ("tornado",),
    "sanic": ("sanic",),
    "bottle": ("bottle",),
    "celery": ("celery",),
    "sqlalchemy": ("sqlalchemy",),
    "pyjwt": ("jwt",),
    "boto3": ("aws",),
    # Ruby
    "rails": ("rails",),
    "sinatra": ("sinatra",),
    # PHP
    "laravel/framework": ("laravel",),
    "symfony/framework-bundle": ("symfony",),
    "slim/slim": ("slim",),
    # Go
    "github.com/gin-gonic/gin": ("gin",),
    "github.com/labstack/echo": ("echo",),
    "github.com/gofiber/fiber": ("fiber",),
    "github.com/go-chi/chi": ("chi",),
    "github.com/gorilla/mux": ("gorilla",),
    "google.golang.org/grpc": ("grpc",),
    # JVM
    "org.springframework": ("spring",),
    "io.ktor": ("ktor",),
}

#: Filename (lowercased basename) or relative path fragment -> tags.
FILE_MARKERS: Dict[str, Sequence[str]] = {
    "manage.py": ("django",),
    "next.config.js": ("nextjs",),
    "next.config.ts": ("nextjs",),
    "next.config.mjs": ("nextjs",),
    "nuxt.config.ts": ("nuxt",),
    "svelte.config.js": ("sveltekit",),
    "artisan": ("laravel",),
    "gemfile": ("ruby",),
    "config/routes.rb": ("rails",),
    "dockerfile": ("docker",),
    "docker-compose.yml": ("compose",),
    "docker-compose.yaml": ("compose",),
    "compose.yml": ("compose",),
    "compose.yaml": ("compose",),
    "kubernetes": ("kubernetes",),
    "serverless.yml": ("serverless",),
    "vercel.json": ("vercel",),
    "netlify.toml": ("netlify",),
    "procfile": ("heroku",),
}

#: Path suffix -> tags, for markers that are directories or nested paths.
PATH_MARKERS: Dict[str, Sequence[str]] = {
    ".github/workflows/": ("github-actions",),
    ".gitlab-ci.yml": ("gitlab-ci",),
    "app/build.gradle": ("gradle", "jvm"),
    "pom.xml": ("maven", "jvm"),
    "androidmanifest.xml": ("android",),
    "terraform/": ("terraform",),
}

#: Tags we emit for context but write no guidance for. Detecting that a project
#: uses Prisma or Passport is useful in a report; pretending to have framework
#: specific advice about it would not be. Listing them explicitly keeps a typo in
#: a marker table from silently looking like a deliberate omission.
INFORMATIONAL_TAGS = {
    "aiohttp", "android", "aws", "bottle", "gitlab-ci", "gorilla", "gradle",
    "grpc", "heroku", "jvm", "jwt", "knex", "koa", "ktor", "maven", "mongoose",
    "netlify", "nuxt", "passport", "prisma", "remix", "ruby", "sanic",
    "sequelize", "serverless", "sinatra", "slim", "sqlalchemy", "starlette",
    "sveltekit", "symfony", "tornado", "vercel",
}

CATALOGUE: Dict[str, Tech] = {
    "nextjs": Tech(
        "nextjs", "Next.js", "typescript",
        entry_hint="app/**/route.ts, pages/api/**, server actions",
        notes=(
            "Middleware is not an authorization boundary. It does not run for every "
            "path by default, and a matcher that misses one route leaves it open.",
            "Server actions are public POST endpoints. Every exported async function "
            "marked 'use server' is callable by anyone who can read the bundle.",
            "Data serialized into the page for hydration is rendered inside a script "
            "tag; unescaped `<\\/script>` in it breaks out.",
            "Search params and headers are attacker-controlled even on server "
            "components.",
        ),
    ),
    "react": Tech(
        "react", "React", "javascript",
        notes=(
            "dangerouslySetInnerHTML on anything that came from a database is stored "
            "XSS - the value was trusted when it was written, not when it is read.",
            "A redirect built from a prop or a ref is an open redirect.",
        ),
    ),
    "express": Tech(
        "express", "Express", "javascript",
        entry_hint="app.get/post/put/delete, router.*",
        notes=(
            "Middleware applies only to routes registered after it. A route declared "
            "above `app.use(requireAuth)` is unauthenticated.",
            "express.static serves whatever is under the directory, including dotfiles "
            "unless told otherwise.",
            "The default error handler returns the stack trace when NODE_ENV is not "
            "'production'.",
        ),
    ),
    "fastify": Tech(
        "fastify", "Fastify", "javascript",
        entry_hint="fastify.get/post/route",
        notes=(
            "Auth belongs in onRequest or preHandler. A check inside the handler runs "
            "after the body has already been parsed and the payload accepted.",
            "Plugin encapsulation means a hook registered inside a plugin does not "
            "apply to routes outside it.",
        ),
    ),
    "nestjs": Tech(
        "nestjs", "NestJS", "typescript",
        entry_hint="@Controller classes, @Get/@Post methods",
        notes=(
            "A controller method with no @UseGuards inherits only the global guard - "
            "check whether one is actually registered.",
            "@Body() without a DTO and a validation pipe accepts arbitrary shapes.",
        ),
    ),
    "hono": Tech(
        "hono", "Hono", "typescript",
        entry_hint="app.get/post, app.route",
        notes=(
            "Middleware ordering decides coverage, as in Express.",
            "Edge runtime handlers often talk to a backend that trusts them - the "
            "trust boundary moves rather than disappearing.",
        ),
    ),
    "django": Tech(
        "django", "Django", "python",
        entry_hint="urls.py patterns, views.py",
        notes=(
            "@csrf_exempt on a state-changing view removes the only thing standing "
            "between it and a cross-site POST.",
            ".raw() and .extra() do not escape interpolated values; only params= binds.",
            "mark_safe on a runtime value asserts something the code cannot know.",
            "A ModelForm with `fields = '__all__'` is mass assignment.",
            "DEBUG=True serves a full traceback with settings to anyone who errors it.",
        ),
    ),
    "drf": Tech(
        "drf", "Django REST Framework", "python",
        entry_hint="ViewSet and APIView classes",
        notes=(
            "A view without permission_classes falls back to DEFAULT_PERMISSION_CLASSES, "
            "which is AllowAny unless someone changed it.",
            "get_queryset that does not filter by the request user is an IDOR on every "
            "detail route the router generates.",
        ),
    ),
    "flask": Tech(
        "flask", "Flask", "python",
        entry_hint="@app.route, @blueprint.route",
        notes=(
            "Decorator order matters: @login_required must sit below @app.route or it "
            "never runs.",
            "render_template_string on request data is server-side template injection, "
            "which reaches Python objects and therefore the process.",
            "A hardcoded secret_key lets anyone forge a session cookie.",
            "send_from_directory confines the path; send_file does not.",
        ),
    ),
    "fastapi": Tech(
        "fastapi", "FastAPI", "python",
        entry_hint="@app.get/post, APIRouter",
        notes=(
            "Auth is a dependency. A route with no Depends(...) is public, and nothing "
            "in the signature says so.",
            "No response_model means the whole ORM object is serialized, including the "
            "fields nobody meant to expose.",
            "A parameter typed Any or dict skips validation entirely.",
        ),
    ),
    "rails": Tech(
        "rails", "Rails", "ruby",
        entry_hint="config/routes.rb, app/controllers",
        notes=(
            "skip_before_action :authenticate_user! is the fastest way to make a "
            "controller public; check every occurrence.",
            "permit! and params.to_unsafe_h defeat strong parameters.",
            "html_safe and raw disable escaping on the value they are given.",
        ),
    ),
    "laravel": Tech(
        "laravel", "Laravel", "php",
        entry_hint="routes/*.php, app/Http/Controllers",
        notes=(
            "$request->all() into a model is mass assignment unless $fillable is tight.",
            "DB::raw and whereRaw interpolate; only bindings are escaped.",
            "VerifyCsrfToken::$except removes CSRF for the paths it lists.",
            "Blade renders {!! !!} unescaped, unlike {{ }} - so the two look "
            "almost identical in a diff and behave completely differently.",
        ),
    ),
    "gin": Tech(
        "gin", "Gin", "go",
        entry_hint="router.GET/POST, gin.Group",
        notes=(
            "Middleware applies to the group it was registered on, in order.",
            "gin.Default() enables the debug logger and recovery handler; release mode "
            "is opt-in.",
        ),
    ),
    "echo": Tech("echo", "Echo", "go", entry_hint="e.GET/POST, Group",
                 notes=("e.Use applies only to routes registered after it, and a "
                        "group inherits only what was registered before the group.",
                        "c.Bind fills whatever fields the target struct exposes, "
                        "including ones the endpoint never meant to accept.")),
    "fiber": Tech("fiber", "Fiber", "go", entry_hint="app.Get/Post",
                  notes=("Request body memory is reused after the handler returns; "
                         "retaining a slice of it yields another request's data.",)),
    "chi": Tech("chi", "chi", "go", entry_hint="r.Get/Post, r.Mount",
                notes=("r.Mount does not inherit the parent router's middleware the way "
                       "people expect - check each subrouter separately.",)),
    "spring": Tech(
        "spring", "Spring", "java",
        entry_hint="@RestController, @RequestMapping",
        notes=(
            "Security matchers are evaluated in order and the first match wins; a "
            "permitAll on /** above a rule makes the rule unreachable.",
            "Actuator endpoints expose environment and heap dumps unless restricted.",
        ),
    ),
    "graphql": Tech(
        "graphql", "GraphQL", "*",
        entry_hint="resolvers, schema definitions",
        notes=(
            "Authorization belongs on every resolver, not on the HTTP endpoint - one "
            "query reaches many types.",
            "Without a depth or cost limit, a recursive query against a cyclic schema "
            "exhausts the server.",
        ),
    ),
    "celery": Tech("celery", "Celery", "python", entry_hint="@task functions",
                   notes=("Task arguments come off a broker. If anything user-controlled "
                          "reaches a task, the broker is an ingress point.",)),
    "bullmq": Tech("bullmq", "BullMQ", "typescript", entry_hint="Worker/Queue processors",
                   notes=("Job data is an ingress surface with no HTTP layer in front "
                          "of it to validate anything.",)),
    "socketio": Tech("socketio", "Socket.IO", "javascript", entry_hint="socket.on handlers",
                     notes=("Handshakes are not covered by the same-origin policy; check "
                            "the origin explicitly.",
                            "Every socket.on is an unauthenticated endpoint unless the "
                            "connection was authenticated first.")),
    "docker": Tech("docker", "Docker", "*", notes=()),
    "compose": Tech("compose", "Docker Compose", "*", notes=()),
    "kubernetes": Tech("kubernetes", "Kubernetes", "*", notes=()),
    "terraform": Tech("terraform", "Terraform", "*", notes=()),
    "github-actions": Tech("github-actions", "GitHub Actions", "*", notes=()),
}

MANIFEST_FILES = {
    "package.json", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
    "pipfile", "setup.py", "gemfile", "composer.json", "go.mod", "pom.xml",
    "build.gradle", "build.gradle.kts", "cargo.toml",
}


@dataclass
class Detection:
    tags: Set[str] = field(default_factory=set)
    evidence: Dict[str, List[str]] = field(default_factory=dict)

    def add(self, tag: str, why: str) -> None:
        self.tags.add(tag)
        self.evidence.setdefault(tag, [])
        if why not in self.evidence[tag]:
            self.evidence[tag].append(why)

    def technologies(self) -> List[Tech]:
        return [CATALOGUE[tag] for tag in sorted(self.tags) if tag in CATALOGUE]

    def notes(self) -> List[str]:
        out: List[str] = []
        for tech in self.technologies():
            for note in tech.notes:
                out.append(f"{tech.label}: {note}")
        return out

    def to_dict(self) -> Dict[str, object]:
        return {
            "tags": sorted(self.tags),
            "evidence": {tag: list(why) for tag, why in sorted(self.evidence.items())},
            "frameworks": [
                {"tag": t.tag, "label": t.label, "language": t.language,
                 "entry_hint": t.entry_hint, "notes": list(t.notes)}
                for t in self.technologies() if t.notes or t.entry_hint
            ],
        }


_DEP_LINE = re.compile(r"^\s*([A-Za-z0-9][\w.\-/]*)", re.MULTILINE)


def _dependencies_in(text: str, filename: str) -> Set[str]:
    """Dependency names declared in a manifest, lowercased."""
    names: Set[str] = set()
    if filename == "package.json" or filename == "composer.json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return names
        for section in ("dependencies", "devDependencies", "peerDependencies",
                        "require", "require-dev"):
            block = data.get(section)
            if isinstance(block, dict):
                names.update(name.lower() for name in block)
        return names

    # Everything else is line-oriented enough that one pass does the job.
    for line in text.splitlines():
        stripped = line.split("#")[0].strip()
        if not stripped:
            continue
        match = _DEP_LINE.match(stripped)
        if match:
            names.add(match.group(1).lower())
        # go.mod and gradle put the name second on the line.
        parts = stripped.replace("'", " ").replace('"', " ").split()
        for part in parts:
            if "/" in part or "." in part:
                names.add(part.lower().rstrip(","))
    return names


def detect(files: Sequence[SourceFile]) -> Detection:
    """Identify the frameworks this repository is built with."""
    found = Detection()

    for source in files:
        relative = source.path.replace("\\", "/")
        lowered = relative.lower()
        basename = os.path.basename(lowered)

        for marker, tags in FILE_MARKERS.items():
            # A marker may be a bare filename ("manage.py") or a path
            # ("config/routes.rb"), and a path marker at the repository root has
            # no leading slash to match against.
            if basename == marker or lowered == marker or lowered.endswith("/" + marker):
                for tag in tags:
                    found.add(tag, relative)
        for marker, tags in PATH_MARKERS.items():
            if marker in lowered:
                for tag in tags:
                    found.add(tag, relative)

        if basename in MANIFEST_FILES:
            try:
                text = source.read()
            except (OSError, UnicodeDecodeError):
                continue
            declared = _dependencies_in(text, basename)
            for dependency, tags in DEPENDENCY_MARKERS.items():
                if dependency.lower() in declared:
                    for tag in tags:
                        found.add(tag, f"{relative} declares {dependency}")

    return found


def summarize(detection: Detection) -> str:
    if not detection.tags:
        return "no frameworks detected"
    labels = [CATALOGUE[tag].label if tag in CATALOGUE else tag for tag in sorted(detection.tags)]
    return ", ".join(labels)
