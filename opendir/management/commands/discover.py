from django.core.management.base import BaseCommand, CommandError
from opendir.discovery.base import ingest_candidates
from opendir.discovery.censys import CensysSource
from opendir.discovery.shodan import ShodanSource


class Command(BaseCommand):
    help = "Discover candidate open directories from a source."

    def add_arguments(self, parser):
        parser.add_argument("--source", choices=["censys", "shodan"], required=True)
        parser.add_argument("--query", required=True)
        parser.add_argument("--max-pages", type=int, default=5)

    def handle(self, *args, **opts):
        if opts["source"] == "censys":
            source = CensysSource(query=opts["query"], max_pages=opts["max_pages"])
        elif opts["source"] == "shodan":
            source = ShodanSource(query=opts["query"], max_pages=opts["max_pages"])
        else:
            raise CommandError(f"unknown source {opts['source']}")
        created = ingest_candidates(source)
        self.stdout.write(f"created {created} new candidates")
