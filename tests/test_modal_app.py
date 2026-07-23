import opendir.capture.modal_app as m


def test_modal_app_imports_offline():
    assert m.app.name == "opendir-fetch"
    assert callable(getattr(m.remote_fetch, "remote", None)) or m.remote_fetch is not None
    assert callable(getattr(m.remote_capture, "remote", None)) or m.remote_capture is not None
