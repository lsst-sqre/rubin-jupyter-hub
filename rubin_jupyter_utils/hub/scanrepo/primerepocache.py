from .singletonscanner import SingletonScanner


def prime_repo_cache(cfg):
    scr = SingletonScanner(
        debug=cfg.debug,
        json=True,
        host=cfg.lab_repo_host,
        owner=cfg.lab_repo_owner,
        name=cfg.lab_repo_name,
        cachefile=cfg.prepuller_cachefile,
        experimentals=cfg.prepuller_experimentals,
        dailies=cfg.prepuller_dailies,
        weeklies=cfg.prepuller_weeklies,
        releases=cfg.prepuller_releases,
    )
    scr.scan()
