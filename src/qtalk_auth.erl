%%%----------------------------------------------------------------------
%%%%%% File    : ejabberd_auth_sql.erl
%%%%%% Purpose : auth qtalk key
%%%%%%----------------------------------------------------------------------
%%%

-module(qtalk_auth).

-export([check_user_password/3]).

-include("ejabberd.hrl").
-include("logger.hrl").

check_user_password(Host, User, Password) ->
    R = case qtalk_sql:get_password_salt_by_host(Host, User) of
        {selected,_, [[Password1, Salt]]} -> 
            case catch rsa:dec(base64:decode(Password)) of
                Json when is_binary(Json) ->
                    {ok,{obj,L},[]} = rfc4627:decode( Json),
                    Pass = proplists:get_value("p",L),
                    Key = proplists:get_value("mk",L),
                    case Key of
                        undefined -> ok;
                    _->
                        NewKey = qtalk_public:concat(User,<<"@">>,Host),
                        catch set_user_mac_key(Host,NewKey,Key)
                    end,
                    do_check_host_user(Password1,Pass, Salt);
               _ -> false
           end;
        _ -> false
    end,

    R.

do_check_host_user(<<"CRY:", _>>, _, null) -> false;
do_check_host_user(<<"CRY:", Password/binary>>,Pass, Salt) ->
    P1 = do_md5(Pass),
    P2 = do_md5(<<P1/binary, Salt/binary>>),
    do_md5(P2) =:= Password;
do_check_host_user(Password, Password, _) -> true;
do_check_host_user(_, _, _) -> false.


do_md5(S) ->
     p1_sha:to_hexlist(erlang:md5(S)).

set_user_mac_key(Server,User,Key) ->
    UTkey = str:concat(User,<<"_tkey">>),
    case redis_link:redis_cmd(Server,2,["HKEYS",UTkey]) of
    {ok,L} when is_list(L) ->
        case lists:member(Key,L) of
        true ->
            lists:foreach(fun(K) ->
                    catch redis_link:hash_del(Server,2,UTkey,K) end,L -- [Key]);
        _ ->
            lists:foreach(fun(K) ->
                    catch redis_link:hash_del(Server,2,UTkey,K) end,L -- [Key]),
            catch redis_link:hash_set(Server,2,UTkey,Key,qtalk_public:get_timestamp())
        end;
    _ ->
        catch redis_link:hash_set(Server,2,UTkey,Key,qtalk_public:get_timestamp())
    end.
