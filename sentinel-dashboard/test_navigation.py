from html.parser import HTMLParser

import pytest

from app import app


class NavigationParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_navigation = False
        self.links = {}
        self.views = set()
        self.initial_active_link = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        classes = attributes.get("class", "").split()
        if tag == "nav" and "nav" in classes:
            self.in_navigation = True
        if self.in_navigation and tag == "a" and "data-view-target" in attributes:
            target = attributes["data-view-target"]
            self.links[target] = attributes.get("href")
            if attributes.get("aria-current") == "page":
                self.initial_active_link = target
        if "data-view" in attributes:
            self.views.add(attributes.get("id"))

    def handle_endtag(self, tag):
        if tag == "nav":
            self.in_navigation = False


@pytest.fixture
def dashboard_navigation():
    response = app.test_client().get("/")
    assert response.status_code == 200
    parser = NavigationParser()
    parser.feed(response.get_data(as_text=True))
    return parser


@pytest.mark.parametrize("view", ["overview", "alerts", "threats", "intel", "reports"])
def test_each_navigation_tab_targets_an_existing_view(dashboard_navigation, view):
    assert dashboard_navigation.links[view] == f"#{view}"
    assert view in dashboard_navigation.views


def test_overview_is_the_initial_active_navigation_tab(dashboard_navigation):
    assert dashboard_navigation.initial_active_link == "overview"
    assert set(dashboard_navigation.links) == {"overview", "alerts", "threats", "intel", "reports"}