use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::Mutex,
};

use bitmaps::{Bitmap, Bits, BitsImpl};

#[macro_export]
macro_rules! box_slab {
    ($name:ident,$t:ty,$v:expr) => {
        use std::sync::Once;
        use $crate::{BoxSlab,Slab};

        pub struct $name;
        impl $name {
            pub fn get_slab() -> &'static Slab<$v, $t> {
                static mut SLAB_SPACE: Option<Slab<$v, $t>> = None;
                static mut INIT: Once = Once::new();
                unsafe {
                    INIT.call_once(|| {
                        SLAB_SPACE = Some(Slab::<$v, $t>::new());
                    });
                    SLAB_SPACE.as_ref().unwrap()
                }
            }

            pub fn alloc(val: $t) -> Option<BoxSlab<$v, $t>> {
                Self::get_slab().alloc(val)
            }
        }
    };
}

pub struct Inner<const N: usize, T>
where
    BitsImpl<N>: Bits,
{
    slab: [MaybeUninit<T>; N],
    map: Bitmap<N>,
}

// Instead of a mutex, we should replace this with a CAS loop
pub struct Slab<const N: usize, T>(Mutex<Inner<N, T>>)
where
    BitsImpl<N>: Bits;

impl<const N: usize, T: 'static> Slab<N, T>
where
    BitsImpl<N>: Bits,
{
    const INIT: MaybeUninit<T> = MaybeUninit::uninit();
    pub fn new() -> Self {
        Self(Mutex::new(Inner {
            slab: [Slab::INIT; N],
            map: Bitmap::<N>::new(),
        }))
    }

    pub fn alloc(&'static self, new_object: T) -> Option<BoxSlab<N, T>> {
        let mut inner = self.0.lock().unwrap();
        if let Some(index) = inner.map.first_false_index() {
            inner.map.set(index, true);
            inner.slab[index].write(new_object);
            let cell_ptr = unsafe { &mut *inner.slab[index].as_mut_ptr() };
            Some(BoxSlab {
                slab: self,
                data: cell_ptr,
                index,
            })
        } else {
            None
        }
    }

    pub fn free(&'static self, index: usize) {
        let mut inner = self.0.lock().unwrap();
        inner.map.set(index, false);
        let old_value = std::mem::replace(&mut inner.slab[index], MaybeUninit::uninit());
        let _old_value = unsafe { old_value.assume_init() };
        // This will drop the old_value
    }
}

pub struct BoxSlab<const N: usize, T: 'static>
where
    BitsImpl<N>: Bits,
{
    // XXX TODO:
    // - We should get rid of this by creating a Trait (that is implemented by the pool, that returns the slab pointer)
    // - We should figure out a way to get rid of the index too
    slab: &'static Slab<N, T>,
    // Because the data is a reference within the MaybeUninit, we don't have a mechanism
    // to go out to the MaybeUninit from this reference. Hence this index
    index: usize,
    data: &'static mut T,
}

impl<const N: usize, T: 'static> Drop for BoxSlab<N, T>
where
    BitsImpl<N>: Bits,
{
    fn drop(&mut self) {
        self.slab.free(self.index);
    }
}

impl<const N: usize, T: 'static> Deref for BoxSlab<N, T>
where
    BitsImpl<N>: Bits,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.data
    }
}

impl<const N: usize, T: 'static> DerefMut for BoxSlab<N, T>
where
    BitsImpl<N>: Bits,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use bitmaps::Bitmap;
    use std::{ops::Deref, sync::Arc};

    use crate::Slab;

    pub struct Test {
        val: Arc<u32>,
    }

    box_slab!(TestSlab, Test, 3);

    #[test]
    fn simple_alloc_free() {
        {
            let a = TestSlab::alloc(Test { val: Arc::new(10) }).unwrap();
            assert_eq!(*a.val.deref(), 10);
            let inner = TestSlab::get_slab().0.lock().unwrap();
            assert_eq!(inner.map.is_empty(), false);
        }
        // Validates that the 'Drop' got executed
        let inner = TestSlab::get_slab().0.lock().unwrap();
        assert_eq!(inner.map.is_empty(), true);
        println!("Box Size {}", std::mem::size_of::<Box<Test>>());
        println!("BoxSlab Size {}", std::mem::size_of::<BoxSlab<3, Test>>());
    }

    #[test]
    fn alloc_full_block() {
        {
            let a = TestSlab::alloc(Test { val: Arc::new(10) }).unwrap();
            let b = TestSlab::alloc(Test { val: Arc::new(11) }).unwrap();
            let c = TestSlab::alloc(Test { val: Arc::new(12) }).unwrap();
            // Test that at overflow, we return None
            assert_eq!(TestSlab::alloc(Test { val: Arc::new(13) }).is_none(), true);
            assert_eq!(*b.val.deref(), 11);

            {
                let inner = TestSlab::get_slab().0.lock().unwrap();
                // Test that the bitmap is marked as full
                assert_eq!(inner.map.is_full(), true);
            }

            // Purposefully drop, to test that new allocation is possible
            std::mem::drop(b);
            let d = TestSlab::alloc(Test { val: Arc::new(21) }).unwrap();
            assert_eq!(*d.val.deref(), 21);

            // Ensure older allocations are still valid
            assert_eq!(*a.val.deref(), 10);
            assert_eq!(*c.val.deref(), 12);
        }

        // Validates that the 'Drop' got executed - test that the bitmap is empty
        let inner = TestSlab::get_slab().0.lock().unwrap();
        assert_eq!(inner.map.is_empty(), true);
    }

    #[test]
    fn test_drop_logic() {
        let root = Arc::new(10);
        {
            let _a = TestSlab::alloc(Test { val: root.clone() }).unwrap();
            let _b = TestSlab::alloc(Test { val: root.clone() }).unwrap();
            let _c = TestSlab::alloc(Test { val: root.clone() }).unwrap();
            assert_eq!(Arc::strong_count(&root), 4);
        }
        // Test that Drop was correctly called on all the members of the pool
        assert_eq!(Arc::strong_count(&root), 1);
    }

    #[test]
    fn test_bitmap() {
        let mut a = Bitmap::<2>::new();
        a.set(0, true);
        a.set(1, true);
        assert_eq!(a.first_false_index(), None);
        assert_eq!(a.is_full(), true);
    }
}
