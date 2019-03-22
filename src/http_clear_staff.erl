-module(http_clear_staff).

-export([handle/1]).
-include("ejabberd.hrl").
-include("logger.hrl").

handle(Req) ->
    Method = cowboy_req:method(Req),
    case Method of 
        <<"POST">> -> send_notify(Req);
        _ -> http_utils:cowboy_req_reply_json(http_utils:gen_fail_result(1, <<Method/binary, " is not disable">>), Req)
    end.

send_notify(Req)->
    {ok, Body, Req1} = http_utils:read_body(Req),
    case rfc4627:decode(Body) of
        {ok, {obj, Args},[]} ->
            Host = proplists:get_value("host",Args),
            Users = proplists:get_value("users",Args),
            clear_staff(Host, Users),
            http_utils:cowboy_req_reply_json(http_utils:gen_success_result(), Req1);
        _ ->
            http_utils:cowboy_req_reply_json(http_utils:gen_fail_result(1, <<"Josn parse error">>), Req1)
    end.

clear_staff(_, []) -> ok;
clear_staff(Host, [User|Users]) ->
    case catch ejabberd_sql:sql_query([<<"select username,muc_name from muc_room_users where username = '", User, "' and hire_flag=0;">>]) of 
        {selected,[<<"username">>,<<"muc_name">>],Res} when is_list(Res) ->
            lists:foreach(fun([U,M]) ->
                case jlib:make_jid(U, Host, <<"">>) of
                    error -> ?INFO_MSG("Make User Jid Error ~p ~n",[U]);
                    JID ->
                        ServerHost =  str:concat(<<"conference.">>,Server),
                        case mod_muc_redis:get_muc_room_pid(M,ServerHost) of
                            [] ->
                                catch qtalk_public:clear_ets_muc_room_users(M,U,Server),
                                catch qtalk_sql:del_muc_user(Server,M,<<"conference.ejabhost1">>,U),
                                catch ejabberd_sql:sql_query(Host, [<<"delete from user_register_mucs where username = '">>,U,<<"' and muc_name = '">>,M,<<"';">>]);
                            [Muc] ->
                                ?INFO_MSG("Remove dimission User ~p ,Muc ~p ~n",[U,M]),
                                Muc#muc_online_room.pid ! {http_del_user,JID}
                        end
                end
            end, Res);
        _ -> ok
    end.

