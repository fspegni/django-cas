"""CAS authentication middleware"""

from urllib import urlencode
import urllib

from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import login, logout
from django.core.urlresolvers import reverse

from django_cas.views import login as cas_login, logout as cas_logout, _service_url

__all__ = ['CASMiddleware']



class CASMiddleware(object):
    """Middleware that allows CAS authentication on admin pages"""

    def process_request(self, request):
        """Logs in the user if a ticket is append as parameter"""

#        print "in process request.."

#        print "request meta: %s" % request.META

        ticket = request.REQUEST.get('ticket')
    
#        print "ticket = %s" % ticket


        if ticket:
#            print "do authenticate ..."
            from django.contrib import auth
            user = auth.authenticate(ticket=ticket, service=_service_url(request))
#            print "returned user: %s ..." % user
            if user is not None:
                auth.login(request, user)


    def process_view(self, request, view_func, view_args, view_kwargs):
        """Forwards unauthenticated requests to the admin page to the CAS
        login URL, as well as calls to django.contrib.auth.views.login and
        logout.
        """

#        print "in process view: %s (%s)..." % (view_func, type(view_func))

        if view_func == login:
#            print "func is login ..."
            return cas_login(request, *view_args, **view_kwargs)
        elif view_func == logout:
#            print "func is logout..."
            return cas_logout(request, *view_args, **view_kwargs)

        if settings.CAS_ADMIN_PREFIX:
            if not request.path.startswith(settings.CAS_ADMIN_PREFIX):
#                return self._cas_gateway(request, view_func)
                return None
        elif not view_func.__module__.startswith('django.contrib.admin.'):
#            return self._cas_gateway(request, view_func)
            return None

        if request.user.is_authenticated():
            if request.user.is_staff:
                return None
            else:
                error = ('<h1>Forbidden</h1><p>You do not have staff '
                         'privileges.</p>')
                return HttpResponseForbidden(error)

        params = urlencode({REDIRECT_FIELD_NAME: request.get_full_path()})
        return HttpResponseRedirect(reverse(cas_login) + '?' + params)


class CASWithGatewayMiddleware(CASMiddleware):

    def process_view(self, request, view_func, view_args, view_kwargs):

        res = super(CASWithGatewayMiddleware, self).process_view(request,
                view_func, view_args, view_kwargs)

        if res == None:
            res = self._cas_gateway(request, view_func)

        return res
   

    def _cas_gateway(self, request, view_func):

        if request.user and request.user.is_authenticated():
            return None

        if view_func == cas_login or view_func == cas_logout:
#            print "found cas_login/cas_logout ... exit ..."
            return None

        gw_param = getattr(settings, "CAS_GATEWAY_PARAMETER", "gateway")
        gw_loop_param = getattr(settings, "CAS_GATEWAY_LOOP_PARAMETER", "gateway")

        gateway = request.REQUEST.get(gw_loop_param, "1")
        ticket = request.REQUEST.get("ticket","")

#        print "gateway: %s" % gateway
#        print "ticket: %s" % ticket

        if gateway != "0":
            orig_params = request.GET.copy()
            if gw_loop_param in orig_params:
                del orig_params[gw_loop_param]
#            print "gateway mode (URI: %s)..." % request.build_absolute_uri()

            params = urlencode({ "service": "http://" + request.get_host() + "/?%s=0" % gw_loop_param })
            url = settings.CAS_SERVER_URL + ('login?%s=1&' % gw_param) + params
#            print "redirect to: %s" % url
            return HttpResponseRedirect(url)

        else:
            return None




