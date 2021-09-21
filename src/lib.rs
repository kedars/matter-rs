pub mod sbox {
    pub fn sbox_new<T> (var: T) -> Result<Box<T>, &'static str> {
        // Always success for now, since Box:new() always succeeds
        Ok(Box::new(var))
    }
}

pub mod data_model {
    use crate::sbox;
    use std::borrow::BorrowMut;
    
    pub const ENDPTS_PER_ACC:     usize = 1;
    pub const CLUSTERS_PER_ENDPT: usize = 4;
    pub const ATTRS_PER_CLUSTER:  usize = 4;

    #[derive(Debug)]
    pub enum AttrValue {
        Int(i64),
        Uint(u64),
        Bool(bool),
    }
    
    #[derive(Debug)]
    pub struct Attribute {
        id: u32,
        value: AttrValue,
    }

    impl Default for Attribute {
        fn default() -> Attribute {
            Attribute { id: 0, value: AttrValue::Bool(true)}
        }
    }
    
    #[derive(Debug, Default)]
    pub struct Cluster {
        id: u32,
        attributes: [Attribute; ATTRS_PER_CLUSTER],
    }

    impl Cluster {
        pub fn new (id: u32) -> Result<Box<Cluster>, &'static str> {
            let mut a = sbox::sbox_new(Cluster::default())?;
            a.id = id;
            Ok(a)
        }
    }

    #[derive(Debug, Default)]
    pub struct Endpoint {
        id: u32,
        clusters: [Option<Box<Cluster>>; CLUSTERS_PER_ENDPT],
    }

    impl Endpoint {
        pub fn new (id: u32) -> Result<Box<Endpoint>, &'static str> {
            let mut a = sbox::sbox_new(Endpoint::default())?;
            a.id = id;
            Ok(a)
        }

        pub fn add_cluster(&mut self, id: u32) -> Result<&mut Cluster, &'static str> {
            for c in self.clusters.iter_mut() {
                if let None = c {
                    let a = Cluster::new(id)?;
                    *c = Some(a);
                    return Ok(c.as_mut().unwrap().borrow_mut());
                }
            }
            return Err("No space available");
        }
    }

    #[derive(Debug, Default)]
    pub struct Accessory {
        endpoints: [Option<Box<Endpoint>>; ENDPTS_PER_ACC],
    }

    impl Accessory {
        pub fn add_endpoint(&mut self, id: u32) -> Result<&mut Endpoint, &'static str> {
            for e in self.endpoints.iter_mut() {
                if let None = e {
                    let a = Endpoint::new(id)?;
                    *e = Some(a);
                    return Ok(e.as_mut().unwrap().borrow_mut());
                }
            }
            return Err("Hit Endpoint Limit");
        }

        pub fn add_cluster(&mut self, id: u32) -> Result<&mut Cluster, &'static str> {
            if let None = self.endpoints[0] {
                self.add_endpoint(1)?;
            }
            self.endpoints[0].as_mut().unwrap().add_cluster(id)
        }
    }

}
