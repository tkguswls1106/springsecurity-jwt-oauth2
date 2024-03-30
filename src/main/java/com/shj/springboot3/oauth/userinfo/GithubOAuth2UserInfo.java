package com.shj.springboot3.oauth.userinfo;

import java.util.Map;

public class GithubOAuth2UserInfo extends OAuth2UserInfo {
    // 깃허브의 경우에는, 네이버,카카오와는 달리 유저 정보가 감싸져 있지 않기 때문에,
    // 바로 get으로 유저 정보 Key를 사용해서 꺼내면 된다.

    public GithubOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        return String.valueOf(attributes.get("id"));
        // 이때, getId는 Long으로 반환되어 (String)으로 캐스팅될 수 없으므로, String.valueOf()를 사용하여 캐스팅해주었음.
    }

    @Override
    public String getNickname() {
        return (String) attributes.get("name");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("avatar_url");
    }
}

/*
- 깃허브의 유저 정보 Response JSON 예시 -
{
     'avatar_url': 'https://avatars.githubusercontent.com/u/97098000?v=4',
     'bio': 'I make things',
     'blog': 'https://noisrucer.github.io/',
     'company': None,
     'created_at': '2022-01-04T11:17:33Z',
     'email': 'changjin9792@gmail.com',
     'events_url': 'https://api.github.com/users/noisrucer/events{/privacy}',
     'followers': 30,
     'followers_url': 'https://api.github.com/users/noisrucer/followers',
     'following': 20,
     'following_url': 'https://api.github.com/users/noisrucer/following{/other_user}',
     'gists_url': 'https://api.github.com/users/noisrucer/gists{/gist_id}',
     'gravatar_id': '',
     'hireable': None,
     'html_url': 'https://github.com/noisrucer',
     'id': 97098000, <---------------- 고유 ID
     'location': None,
     'login': 'noisrucer',
     'name': 'Changjin Lee',
     'node_id': 'U_kgDOBcmZEA',
     'organizations_url': 'https://api.github.com/users/noisrucer/orgs',
     'public_gists': 0,
     'public_repos': 35,
     'received_events_url': 'https://api.github.com/users/noisrucer/received_events',
     'repos_url': 'https://api.github.com/users/noisrucer/repos',
     'site_admin': False,
     'starred_url': 'https://api.github.com/users/noisrucer/starred{/owner}{/repo}',
     'subscriptions_url': 'https://api.github.com/users/noisrucer/subscriptions',
     'twitter_username': None,
     'type': 'User',
     'updated_at': '2023-12-13T05:19:36Z'
}
 */