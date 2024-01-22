/* SPDX-License-Identifier: GPL-2.0-only or License-Ref-kk-custom */
/*
 * Copyright (C) 2021-2023 Kernkonzept GmbH.
 * Author(s): Jan Klötzke <jan.kloetzke@kernkonzept.com>
 */

#pragma once

/**
 * Item on an Atomic_fwd_list.
 */
class Atomic_fwd_list_item
{
  template<typename T>
  friend class Atomic_fwd_list;

  enum {
    // Element is not in a list. Distinct from nullptr which is is the end of
    // list.
    Not_in_list = 1,
  };

public:
  Atomic_fwd_list_item()
  : _next(reinterpret_cast<Atomic_fwd_list_item*>(Not_in_list)) {}

  bool in_list() const
  {
    return _next != reinterpret_cast<Atomic_fwd_list_item*>(Not_in_list);
  }

private:
  explicit Atomic_fwd_list_item(Atomic_fwd_list_item *n) : _next(n) {}

  Atomic_fwd_list_item *_next;
};

/**
 * A lock-free, multi producer list.
 *
 * Items that are stored on the list must be derived from Atomic_fwd_list_item.
 * The only supported concurrent methods are push() and swap(). Multiple
 * threads may push(), even the same element, onto a list. On the consumer
 * side, swap() must be used to atomically take ownership of the list and
 * replace it with an empty one. All other methods are *not* thread safe and
 * must only be used after swap() was used to have exclusive access to the
 * list. Internally it is a single linked list.
 */
template<typename T>
class Atomic_fwd_list
{
public:
  Atomic_fwd_list() : _head(nullptr) {}

  class Iterator
  {
    friend class Atomic_fwd_list;

  public:
    Iterator() : _elem(nullptr), _prev_next_ptr(nullptr) {}

    Iterator operator++()
    {
      _prev_next_ptr = &_elem->_next;
      _elem = _elem->_next;
      return *this;
    }

    T *operator*() const { return static_cast<T*>(_elem); }
    T *operator->() const { return static_cast<T*>(_elem); }

    bool operator==(Iterator const &other) const
    { return other._elem == _elem; }
    bool operator!=(Iterator const &other) const
    { return other._elem != _elem; }

  private:
    Iterator(Atomic_fwd_list_item **prev_next_ptr, Atomic_fwd_list_item *elem)
    : _elem(elem), _prev_next_ptr(prev_next_ptr)
    {}

    /**
     * Construct iterator to first element on the list.
     *
     * \param head_next_ptr Pointer to the _next-pointer of the list head.
     */
    explicit Iterator(Atomic_fwd_list_item **head_next_ptr)
    : _elem(*head_next_ptr), _prev_next_ptr(head_next_ptr)
    {}

    /**
     * Construct (invalid) iterator that points to before the first element.
     *
     * \param head Pointer to list head.
     */
    explicit Iterator(Atomic_fwd_list_item *head)
    : _elem(head), _prev_next_ptr(nullptr)
    {}

    /// The current element to which the iterator points.
    Atomic_fwd_list_item *_elem;

    /**
     * Pointer to _next pointer of previous element that points to _elem.
     *
     * For valid iterators "*_prev_next_ptr == _elem" holds.
     */
    Atomic_fwd_list_item **_prev_next_ptr;
  };

  Iterator before_begin() { return Iterator(&_head); }
  Iterator begin() { return Iterator(&_head._next); }
  Iterator end() { return Iterator(); }

  /**
   * Add element to front of list.
   *
   * It is safe against concurrent insert attempts, even of the same element.
   * This is achieved by synchronizing on the _next pointer. Elements that are
   * not on a list are marked as "logically deleted" (Not_in_list), as done by
   * erase(). This guarantees that the object is currently not visible on the
   * list. If setting that pointer fails, some other thread was faster and the
   * element is being inserted currently.
   *
   * We do *not* wait until being inserted if the _next pointer could not be
   * set. It is the responsibility of the caller to cope with the possibility
   * that the element is not yet visible on the list on such concurrent
   * inserts.
   */
  void push(T *e)
  {
    Atomic_fwd_list_item *old_next = __atomic_load_n(&e->_next, __ATOMIC_ACQUIRE);
    if (old_next !=
        reinterpret_cast<Atomic_fwd_list_item*>(Atomic_fwd_list_item::Not_in_list))
      return;

    Atomic_fwd_list_item *first = __atomic_load_n(&_head._next, __ATOMIC_ACQUIRE);
    if (!__atomic_compare_exchange_n(&e->_next, &old_next, first,
                                     false, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
      return;

    // We now "own" the element and must complete the insert. It's not yet
    // visible on the list. There could still be other concurrent inserts on
    // the same list for different elements, though.
    while (!__atomic_compare_exchange_n(&_head._next, &first,
                                        static_cast<Atomic_fwd_list_item*>(e),
                                        true, __ATOMIC_ACQ_REL,
                                        __ATOMIC_ACQUIRE))
      __atomic_store_n(&e->_next, first, __ATOMIC_RELEASE);
  }

  /**
   * Atomically swap this and the other list.
   *
   * The content of this instance must no be manipulated concurrently.
   * Atomicity is only guaranteed wrt. the \a other list.
   */
  void swap(Atomic_fwd_list &other)
  {
    Atomic_fwd_list_item *cur = _head._next;
    Atomic_fwd_list_item *o = __atomic_load_n(&other._head._next,
                                              __ATOMIC_RELAXED);
    while (!__atomic_compare_exchange_n(&other._head._next, &o, cur, false,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
      ;

    _head._next = o;
  }

  /**
   * Remove item from list.
   *
   * This method is *not* thread safe. There must be no concurrent
   * manipulations of the list!
   */
  static Iterator erase(Iterator const &e)
  {
    Iterator ret(e._prev_next_ptr, e._elem->_next);
    *e._prev_next_ptr = e._elem->_next;
    __atomic_store_n(&e._elem->_next,
                     reinterpret_cast<Atomic_fwd_list_item*>(Atomic_fwd_list_item::Not_in_list),
                     __ATOMIC_RELEASE);
    return ret;
  }

  /**
   * Move item from \a other list to this one after \a pos.
   *
   * The moved element is always seen as if it is on a list. Protects against
   * concurrent push() calls for the element that is moved between the lists.
   * This method is *not* thread safe.
   *
   * \return Iterator pointing to element after \a e on the \a other list.
   */
  static Iterator move_after(Iterator const &pos, Atomic_fwd_list& /*other*/,
                             Iterator const &e)
  {
    Iterator ret(e._prev_next_ptr, e._elem->_next);

    *e._prev_next_ptr = e._elem->_next;
    e._elem->_next = pos._elem->_next;
    pos._elem->_next = e._elem;

    return ret;
  }

private:
  Atomic_fwd_list_item _head;
};
