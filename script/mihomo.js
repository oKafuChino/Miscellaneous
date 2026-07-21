function main(config) {
  // 1. 获取订阅中的所有原始代理节点
  const proxies = config.proxies || [];
  const allProxyNames = proxies.map(p => p.name);

  // 2. 节点自动化正则过滤函数（防止因国家分组无节点导致客户端报错崩溃）
  const filterNodes = (regex) => {
    const matched = proxies.filter(p => regex.test(p.name)).map(p => p.name);
    return matched.length > 0 ? matched : ['DIRECT']; 
  };

  const regionNodes = (names, codes) => filterNodes(
    new RegExp(`${names}|(?:^|[\\s\\-_|()[\\]{}【】])(?:${codes})(?=$|[\\s\\-_|()[\\]{}【】])`, 'i')
  );

  // 3. 针对各个国家/地区策略组进行智能动态匹配 (融合了你原本配置中的特殊并组逻辑)
  const hkNodes = regionNodes('香港|Hong.*Kong|🇭🇰', 'HK');
  const twNodes = regionNodes('台湾|Taiwan|🇹🇼', 'TW');
  const sgNodes = regionNodes('新加坡|Singapore|🇸🇬', 'SG');
  const jpNodes = regionNodes('日本|Japan|🇯🇵', 'JP');
  const usNodes = regionNodes('美国|United.*States|🇺🇸', 'US');
  const ukNodes = regionNodes('英国|United.*Kingdom|🇬🇧', 'UK');
  const deNodes = regionNodes('德国|Germany|🇩🇪', 'DE');
  const frNodes = regionNodes('法国|France|🇫🇷|法属', 'FR');
  const moNodes = regionNodes('澳门|Macao|🇲🇴', 'MO');
  const phNodes = regionNodes('菲律宾|Philippines|🇵🇭', 'PH');
  const myNodes = regionNodes('马来西亚|Malaysia|🇲🇾', 'MY');
  const thNodes = regionNodes('泰国|Thailand|🇹🇭', 'TH');
  const auNodes = regionNodes('澳大利亚|澳洲|Australia|🇦🇺', 'AU');
  const krNodes = regionNodes('韩国|Korea|🇰🇷', 'KR');
  const caNodes = regionNodes('加拿大|Canada|🇨🇦', 'CA');
  const arNodes = regionNodes('阿根廷|Argentina|🇦🇷', 'AR');
  const fiNodes = regionNodes('芬兰|Finland|🇫🇮', 'FI');
  const trNodes = regionNodes('土耳其|Turkey|🇹🇷', 'TR');
  const uaNodes = regionNodes('乌克兰|Ukraine|🇺🇦', 'UA');
  const egNodes = regionNodes('埃及|Egypt|🇪🇬', 'EG');
  
  // 按照你原本的配置：印度节点组里包含了印度和印度尼西亚
  const inNodes = regionNodes('印度|India|🇮🇳|印尼|Indonesia|🇮🇩', 'IN|ID');
  // 按照你原本的配置：俄罗斯节点组里包含了俄罗斯和埃塞俄比亚
  const ruNodes = regionNodes('俄罗斯|Russia|🇷🇺|埃塞俄比亚|Ethiopia|🇪🇹', 'RU');

  // 4. 定义通用的区域策略组列表
  const regions = [
    '香港节点', '台湾节点', '新加坡节点', '日本节点', '美国节点',
    '英国节点', '德国节点', '法国节点', '印度节点', '澳门节点',
    '菲律宾节点', '马来西亚节点', '泰国节点', '澳大利亚节点', '韩国节点',
    '加拿大节点', '阿根廷节点', '芬兰节点', '土耳其节点', '俄罗斯节点',
    '乌克兰节点', '埃及节点'
  ];

  // 5. 覆盖全局基础设置与 Geodata 路径
  config['geodata-mode'] = true;
  config['geox-url'] = {
    geoip: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat',
    geosite: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geosite.dat',
    mmdb: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb',
    asn: 'https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/GeoLite2-ASN.mmdb'
  };

  // 6. 覆盖 嗅探器 (Sniffer) 配置
  config['sniffer'] = {
    enable: true,
    'override-destination': false,
    'force-dns-mapping': true,
    'skip-domain': ['Mijia Cloud', 'dlg.io.mi.com', '+.push.apple.com'],
    sniff: {
      TLS: { ports: [443, 8443] },
      HTTP: { ports: [80, 8080, 8880] },
      QUIC: { ports: [443, 8443] }
    }
  };

  // 7. 覆盖 DNS 配置
  config['dns'] = {
    enable: true,
    ipv6: false,
    'prefer-h3': true,
    'enhanced-mode': 'fake-ip',
    'default-nameserver': ['119.29.29.29', '223.5.5.5'],
    nameserver: ['system', '223.5.5.5', '119.29.29.29', '180.184.1.1'],
    fallback: [
      'quic://dns0.eu',
      'https://dns.cloudflare.com/dns-query',
      'https://dns.sb/dns-query',
      'tcp://208.67.222.222',
      'tcp://8.26.56.2'
    ],
    'proxy-server-nameserver': ['https://dns.alidns.com/dns-query', 'tls://dot.pub'],
    'fake-ip-filter': [
      'geosite:private', 'geosite:connectivity-check', 'geosite:cn',
      'Mijia Cloud', 'dig.io.mi.com', 'localhost.ptlogin2.qq.com',
      '*.icloud.com', '*.stun.*.*', '*.stun.*.*.*'
    ]
  };

  // 8. 覆盖 规则集 (Rule Providers)
  config['rule-providers'] = {
    ADBlock: { type: 'http', behavior: 'domain', format: 'mrs', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/217heidai/adblockfilters@main/rules/adblockmihomolite.mrs', path: './ruleset/ADBlock.mrs' },
    SogouInput: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt', path: './ruleset/SogouInput.txt' },
    StaticResources: { type: 'http', behavior: 'domain', format: 'text', interval: 86400, url: 'https://ruleset.skk.moe/Clash/domainset/cdn.txt', path: './ruleset/StaticResources.txt' },
    CDNResources: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://ruleset.skk.moe/Clash/non_ip/cdn.txt', path: './ruleset/CDNResources.txt' },
    TikTok: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list', path: './ruleset/TikTok.list' },
    EHentai: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list', path: './ruleset/EHentai.list' },
    SteamFix: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list', path: './ruleset/SteamFix.list' },
    GoogleFCM: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list', path: './ruleset/FirebaseCloudMessaging.list' },
    AdditionalFilter: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list', path: './ruleset/AdditionalFilter.list' },
    AdditionalCDNResources: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list', path: './ruleset/AdditionalCDNResources.list' },
    Crypto: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list', path: './ruleset/Crypto.list' },
    Weibo: { type: 'http', behavior: 'classical', format: 'text', interval: 86400, url: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Weibo.list', path: './ruleset/Weibo.list' }
  };

  // 9. 构造并生成完整的 策略组 (Proxy Groups)
  const sharedSelectProxies = ['选择代理', ...regions, '手动选择', '直连'];

  config['proxy-groups'] = [
    { name: '选择代理', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Proxy.png', proxies: ['自动选择', '故障转移', ...regions, '手动选择', 'DIRECT'] },
    { name: '手动选择', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/shindgewongxj/WHATSINStash@master/icon/select.png', proxies: allProxyNames.length > 0 ? allProxyNames : ['DIRECT'] },
    
    // 共享相同选择列表的业务分流策略组
    { name: '静态资源', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cloudflare.png', proxies: sharedSelectProxies },
    { name: 'AI服务', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/ChatGPT.png', proxies: sharedSelectProxies },
    { name: '加密货币', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Cryptocurrency_1.png', proxies: sharedSelectProxies },
    { name: '苹果服务', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Apple_2.png', proxies: sharedSelectProxies },
    { name: '谷歌服务', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Orz-3/mini@master/Color/Google.png', proxies: sharedSelectProxies },
    { name: '微软服务', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Microsoft_Copilot.png', proxies: sharedSelectProxies },
    { name: 'Youtube', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/YouTube.png', proxies: sharedSelectProxies },
    { name: 'Netflix', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Netflix.png', proxies: sharedSelectProxies },
    { name: 'TikTok', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/TikTok.png', proxies: sharedSelectProxies },
    { name: 'Spotify', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Spotify.png', proxies: sharedSelectProxies },
    { name: 'Telegram', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Telegram_X.png', proxies: sharedSelectProxies },
    { name: 'Twitter', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Twitter.png', proxies: sharedSelectProxies },
    { name: 'E-Hentai', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Ehentai.png', proxies: sharedSelectProxies },
    { name: 'PikPak网盘', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/icons/PikPak.png', proxies: sharedSelectProxies },
    { name: 'SSH', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Server.png', proxies: sharedSelectProxies },
    { name: 'Nodeseek', type: 'select', icon: 'https://raw.githubusercontent.com/oKafuChino/Miscellaneous/refs/heads/main/icon/nodeseek.png', proxies: sharedSelectProxies },
    { name: 'Roblox', type: 'select', icon: 'https://raw.githubusercontent.com/oKafuChino/Miscellaneous/refs/heads/main/icon/roblox.png', proxies: sharedSelectProxies },

    // 特殊自定义选路的策略组
    { name: '哔哩哔哩', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/bilibili.png', proxies: ['直连', '台湾节点', '香港节点'] },
    { name: '巴哈姆特', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Bahamut.png', proxies: ['台湾节点', '选择代理', '手动选择', '直连'] },
    { name: '新浪微博', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Weibo.png', proxies: ['直连', ...regions, '选择代理', '手动选择'] },
    { name: 'Truth Social', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Truth_Social.png', proxies: ['美国节点', '选择代理', '手动选择'] },
    { name: '搜狗输入法', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/powerfullz/override-rules@master/icons/Sougou.png', proxies: ['直连', 'REJECT'] },

    // 自动选路组
    { name: '自动选择', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Auto.png', proxies: [...regions, '手动选择', 'DIRECT'] },
    { name: '故障转移', type: 'fallback', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Available_1.png', proxies: [...regions, '手动选择', 'DIRECT'] },
    
    // 基础控制组
    { name: '直连', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Direct.png', proxies: ['DIRECT', '选择代理'] },
    { name: '广告拦截', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/AdBlack.png', proxies: ['REJECT', 'REJECT-DROP', '直连'] },

    // 动态地区节点组（使用上面过滤出来的真实节点数组）
    { name: '香港节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Hong_Kong.png', proxies: hkNodes },
    { name: '台湾节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Taiwan.png', proxies: twNodes },
    { name: '新加坡节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Singapore.png', proxies: sgNodes },
    { name: '日本节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Japan.png', proxies: jpNodes },
    { name: '美国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_States.png', proxies: usNodes },
    { name: '英国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/United_Kingdom.png', proxies: ukNodes },
    { name: '德国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Germany.png', proxies: deNodes },
    { name: '法国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/France.png', proxies: frNodes },
    { name: '印度节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/India.png', proxies: inNodes },
    { name: '澳门节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Macao.png', proxies: moNodes },
    { name: '菲律宾节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Philippines.png', proxies: phNodes },
    { name: '马来西亚节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Malaysia.png', proxies: myNodes },
    { name: '泰国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Thailand.png', proxies: thNodes },
    { name: '澳大利亚节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Australia.png', proxies: auNodes },
    { name: '韩国节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Korea.png', proxies: krNodes },
    { name: '加拿大节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Canada.png', proxies: caNodes },
    { name: '阿根廷节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Argentina.png', proxies: arNodes },
    { name: '芬兰节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Finland.png', proxies: fiNodes },
    { name: '土耳其节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Turkey.png', proxies: trNodes },
    { name: '俄罗斯节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Russia.png', proxies: ruNodes },
    { name: '乌克兰节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Ukraine.png', proxies: uaNodes },
    { name: '埃及节点', type: 'url-test', url: 'https://cp.cloudflare.com/generate_204', interval: 60, tolerance: 20, icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Egypt.png', proxies: egNodes },

    // 带有 include-all 的 GLOBAL 组
    { name: 'GLOBAL', type: 'select', icon: 'https://cdn.jsdelivr.net/gh/Koolson/Qure@master/IconSet/Color/Global.png', 'include-all': true, proxies: ['选择代理', '手动选择', '静态资源', 'AI服务', '加密货币', '苹果服务', '谷歌服务', '微软服务', '哔哩哔哩', '巴哈姆特', 'Youtube', 'Netflix', 'TikTok', 'Spotify', 'Telegram', 'Twitter', '新浪微博', 'Truth Social', 'E-Hentai', 'PikPak网盘', '搜狗输入法', 'SSH', 'Nodeseek', 'Roblox', '自动选择', '故障转移', '直连', '广告拦截', ...regions] }
  ];

  // 10. 覆盖 路由规则 (Rules)
  config['rules'] = [
    'DST-PORT,22,SSH',
    'RULE-SET,ADBlock,广告拦截',
    'RULE-SET,AdditionalFilter,广告拦截',
    'DOMAIN-SUFFIX,nodeseek.com,Nodeseek',
    'DOMAIN-SUFFIX,seek.li,Nodeseek',
    'DOMAIN-KEYWORD,nodeseek,Nodeseek',
    'DOMAIN-SUFFIX,roblox.com,Roblox',
    'DOMAIN-SUFFIX,rbxcdn.com,Roblox',
    'DOMAIN-SUFFIX,rbx.com,Roblox',
    'DOMAIN-SUFFIX,roblox.cn,Roblox',
    'RULE-SET,SogouInput,搜狗输入法',
    'DOMAIN-SUFFIX,truthsocial.com,Truth Social',
    'RULE-SET,StaticResources,静态资源',
    'RULE-SET,CDNResources,静态资源',
    'RULE-SET,AdditionalCDNResources,静态资源',
    'RULE-SET,Crypto,加密货币',
    'RULE-SET,EHentai,E-Hentai',
    'RULE-SET,TikTok,TikTok',
    'RULE-SET,SteamFix,直连',
    'RULE-SET,GoogleFCM,直连',
    'RULE-SET,Weibo,新浪微博',
    'GEOSITE,YOUTUBE,Youtube',
    'GEOSITE,TELEGRAM,Telegram',
    'GEOSITE,GOOGLE-PLAY@CN,直连',
    'GEOSITE,MICROSOFT@CN,直连',
    'GEOSITE,APPLE,苹果服务',
    'GEOSITE,MICROSOFT,微软服务',
    'GEOSITE,GOOGLE,谷歌服务',
    'GEOSITE,NETFLIX,Netflix',
    'GEOSITE,SPOTIFY,Spotify',
    'GEOSITE,BAHAMUT,巴哈姆特',
    'GEOSITE,BILIBILI,哔哩哔哩',
    'GEOSITE,PIKPAK,PikPak网盘',
    'GEOSITE,TWITTER,Twitter',
    'GEOSITE,CATEGORY-AI-!CN,AI服务',
    'GEOSITE,GFW,选择代理',
    'GEOSITE,CN,直连',
    'GEOSITE,PRIVATE,直连',
    'GEOIP,NETFLIX,Netflix,no-resolve',
    'GEOIP,TELEGRAM,Telegram,no-resolve',
    'GEOIP,CN,直连',
    'GEOIP,PRIVATE,直连',
    'MATCH,选择代理'
  ];

  return config;
}
