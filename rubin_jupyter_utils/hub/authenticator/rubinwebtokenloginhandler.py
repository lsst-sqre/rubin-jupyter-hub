"""Rubin Login Handler to use web token present in request headers.
"""
from eliot import start_action
from tornado import gen, web
from jupyterhub.utils import url_path_join
from jwtauthenticator.jwtauthenticator import JSONWebTokenLoginHandler
from rubin_jupyter_utils.helpers import parse_access_token


class RubinWebTokenLoginHandler(JSONWebTokenLoginHandler):
    @gen.coroutine
    def get(self):
        """Authenticate on get() via reading the token from HTTP headers.
        """
        # This causes some token context error in Eliot
        # with start_action(action_type="get"):
        _ = yield self._jwt_authenticate()
        #
        # We can't just use the superclass because it issues the redirect,
        #  and we can't do that until we do our additional checking.
        _url = url_path_join(self.hub.server.base_url, "home")
        next_url = self.get_argument("next", default=False)
        if next_url:
            _url = next_url
        self.redirect(_url)

    @gen.coroutine
    def post(self):
        """Also authenticate on POST, if necessary."""
        with start_action(action_type="post"):
            _ = yield (self._jwt_authenticate())
            yield super().post()

    @gen.coroutine
    def _jwt_authenticate(self):
        # This is taken from https://github.com/mogthesprog/jwtauthenticator
        #  but with our additional claim information checked and stuffed
        #  into auth_state.
        # Gafaelfawr will not give us back an invalid token; we will raise an
        #  error if something goes wrong with the token analysis
        claims, token = yield self._check_auth_header()
        username_claim_field = self.authenticator.username_claim_field
        username = self.retrieve_username(claims, username_claim_field).lower()
        user = self.user_from_username(username)
        # Here is where we deviate from the vanilla JWT authenticator.
        # We simply store all the JWT claims in auth_state, although we
        #  choose our field names to make the spawner reusable from the
        #  OAuthenticator implementation.
        auth_state = yield self.refresh_user(user)
        _ = yield user.save_auth_state(auth_state)
        self.set_login_cookie(user)

    @gen.coroutine
    def refresh_user(self, user, handler=None):
        """Validate the token and force re-auth if the claims are not
        (presumably no longer) valid.
        """
        with start_action(action_type="refresh_user_loginhandler"):
            uname = user.escaped_name
            self.log.debug(
                "Entering refresh_user() on jwtloginhandler for '{}'.".format(
                    uname
                )
            )
            try:
                self.log.debug("Checking auth header for '{}'.".format(uname))
                claims, token = yield self._check_auth_header()
                self.log.debug("Auth header for '{}' is valid.".format(uname))
            except web.HTTPError:
                # Force re-login
                self.log.debug(
                    "Auth header check for '{}' failed.".format(uname)
                )
                return False
            username_claim_field = self.authenticator.username_claim_field
            username = self.retrieve_username(
                claims, username_claim_field
            ).lower()
            auth_state = {
                "id": username,
                "access_token": token,
                "claims": claims,
            }
            self.log.debug(
                "Finished jwtloginhandler refresh_user for '{}'.".format(uname)
            )
            return auth_state

    @gen.coroutine
    def _check_auth_header(self):
        with start_action(action_type="_check_auth_header"):
            # Either returns (valid) claims and token,
            #  or throws a web error of some type.
            self.log.debug("Checking authentication header.")
            auth = self.authenticator
            header_name = auth.header_name
            param_name = auth.param_name
            header_is_authorization = auth.header_is_authorization
            auth_header_content = self.request.headers.get(header_name, "")
            auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
            tokenParam = self.get_argument(param_name, default=False)
            if auth_header_content and tokenParam:
                self.log.error(
                    "Authentication: both an authentication "
                    + "header and tokenParam"
                )
                raise web.HTTPError(400)
            elif auth_header_content:
                if header_is_authorization:
                    # We should not see "token" as first word in the
                    #  authorization header.  If we do it could mean someone
                    #  coming in with a stale API token
                    if auth_header_content.split()[0].lower() != "bearer":
                        self.log.error("Authorization header is not 'bearer'.")
                        raise web.HTTPError(403)
                    token = auth_header_content.split()[1]
                else:
                    token = auth_header_content
            elif auth_cookie_content:
                token = auth_cookie_content
            elif tokenParam:
                token = tokenParam
            else:
                self.log.error("Could not determine authentication token.")
                raise web.HTTPError(401)
            # Delegate to gafaelfawr for validation.
            self.log.debug("Sending token to gafaelfawr for validation.")
            try:
                claims = parse_access_token(token=token)
            except RuntimeError as exc:
                self.log.error("Token validation failed: '{}'".format(exc))
                raise web.HTTPError(403)
            uname = claims["uid"]
            self.log.debug(
                "Gafaelfawr validated token for '{}'.".format(uname)
            )
            return claims, token
