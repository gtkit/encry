package jwt

/**
 * 黑名单接口.
 * @interface Blacklister.
 * @method IsTokenBlacklisted.
 * @param  {[type]}    tokenID string [用户token].
 * @method AddTokenToBlacklist.
 * @param  {[type]}    tokenID string [用户token].
 */
type Blacklister interface {
	In(tokenID string) bool
	Add(tokenID string)
	Remove(tokenID string)
}

type Blacklist map[string]struct{}

// NewBlacklist 新建黑名单.
func NewBlacklist() Blacklist {
	return Blacklist(make(map[string]struct{}))
}

func (b Blacklist) In(tokenID string) bool {
	_, ok := b[tokenID]
	return ok
}

func (b Blacklist) Add(tokenID string) {
	b[tokenID] = struct{}{}
}

func (b Blacklist) Remove(tokenID string) {
	delete(b, tokenID)
}

/**
 * 判断令牌ID是否在黑名单中.
 * @method InBlacklist.
 * @param  {[type]}    tokenID string [用户token].
 */
func (j *JWT) InBlacklist(tokenID string) bool {
	if j.blacklist != nil {
		return j.blacklist.In(tokenID)
	}
	return false
}

/**
 * 将令牌ID加入黑名单.
 * 实际实现应该存储到数据库或Redis中
 * @method AddTokenToBlacklist.
 * @param  {[type]}    tokenID string [用户token id].
 */
func (j *JWT) AddToBlacklist(tokenID string) {
	if j.blacklist != nil {
		j.blacklist.Add(tokenID)
	}
}

/**
 * 从黑名单中移除令牌ID.
 * @method RemoveTokenFromBlacklist.
 * @param  {[type]}    tokenID string [用户token].
 */
func (j *JWT) RemoveFromBlacklist(tokenID string) {
	if j.blacklist != nil {
		j.blacklist.Remove(tokenID)
	}
}
