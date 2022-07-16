use crate::{
    data_model::objects::{ClusterType, Endpoint},
    error::*,
    interaction_model::messages::GenericPath,
    // TODO: This layer shouldn't really depend on the TLV layer, should create an abstraction layer
};
use std::fmt;

pub trait ChangeConsumer {
    fn endpoint_added(&self, id: u16, endpoint: &mut Endpoint) -> Result<(), Error>;
}

pub const ENDPTS_PER_ACC: usize = 3;

#[derive(Default)]
pub struct Node {
    endpoints: [Option<Box<Endpoint>>; ENDPTS_PER_ACC],
    changes_cb: Option<Box<dyn ChangeConsumer>>,
}

impl std::fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "node:")?;
        for (i, element) in self.endpoints.iter().enumerate() {
            if let Some(e) = element {
                writeln!(f, "endpoint {}: {}", i, e)?;
            }
        }
        write!(f, "")
    }
}

impl Node {
    pub fn new() -> Result<Box<Node>, Error> {
        let node = Box::new(Node::default());
        Ok(node)
    }

    pub fn set_changes_cb(&mut self, consumer: Box<dyn ChangeConsumer>) {
        self.changes_cb = Some(consumer);
    }

    pub fn add_endpoint(&mut self) -> Result<u32, Error> {
        let index = self
            .endpoints
            .iter()
            .position(|x| x.is_none())
            .ok_or(Error::NoSpace)?;
        let mut endpoint = Endpoint::new()?;
        if let Some(cb) = &self.changes_cb {
            cb.endpoint_added(index as u16, &mut endpoint)?;
        }
        self.endpoints[index] = Some(endpoint);
        Ok(index as u32)
    }

    pub fn get_endpoint(&self, endpoint_id: u16) -> Result<&Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_ref()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_endpoint_mut(&mut self, endpoint_id: u16) -> Result<&mut Endpoint, Error> {
        if (endpoint_id as usize) < ENDPTS_PER_ACC {
            let endpoint = self.endpoints[endpoint_id as usize]
                .as_mut()
                .ok_or(Error::EndpointNotFound)?;
            Ok(endpoint)
        } else {
            Err(Error::EndpointNotFound)
        }
    }

    pub fn get_cluster_mut(&mut self, e: u16, c: u32) -> Result<&mut dyn ClusterType, Error> {
        self.get_endpoint_mut(e)?.get_cluster_mut(c)
    }

    pub fn get_cluster(&self, e: u16, c: u32) -> Result<&dyn ClusterType, Error> {
        self.get_endpoint(e)?.get_cluster(c)
    }

    pub fn add_cluster(
        &mut self,
        endpoint_id: u32,
        cluster: Box<dyn ClusterType>,
    ) -> Result<(), Error> {
        let endpoint_id = endpoint_id as usize;
        if endpoint_id < ENDPTS_PER_ACC {
            self.endpoints[endpoint_id]
                .as_mut()
                .ok_or(Error::NoEndpoint)?
                .add_cluster(cluster)
        } else {
            Err(Error::Invalid)
        }
    }

    // Returns a slice of endpoints, with either a single endpoint or all (wildcard)
    pub fn get_wildcard_endpoints(
        &self,
        endpoint: Option<u16>,
    ) -> (&[Option<Box<Endpoint>>], usize) {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                // empty slice
                (&[] as &[Option<Box<Endpoint>>], 0_usize)
            } else {
                (&self.endpoints[e..e + 1], e)
            }
        } else {
            (&self.endpoints[..], 0)
        }
    }

    pub fn get_wildcard_endpoints_mut(
        &mut self,
        endpoint: Option<u16>,
    ) -> (&mut [Option<Box<Endpoint>>], usize) {
        if let Some(e) = endpoint {
            let e = e as usize;
            if self.endpoints[e].is_none() {
                // empty slice
                (&mut [] as &mut [Option<Box<Endpoint>>], 0_usize)
            } else {
                (&mut self.endpoints[e..e + 1], e)
            }
        } else {
            (&mut self.endpoints[..], 0)
        }
    }

    pub fn for_each_endpoint<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &Endpoint),
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints(path.endpoint);
        for e in endpoints.iter() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_ref());
            }
            endpoint_id += 1;
        }
    }

    pub fn for_each_endpoint_mut<T>(&mut self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &mut Endpoint),
    {
        let mut current_path = *path;
        let (endpoints, mut endpoint_id) = self.get_wildcard_endpoints_mut(path.endpoint);
        for e in endpoints.iter_mut() {
            if let Some(e) = e {
                current_path.endpoint = Some(endpoint_id as u16);
                f(&current_path, e.as_mut());
            }
            endpoint_id += 1;
        }
    }

    pub fn for_each_cluster<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &dyn ClusterType),
    {
        self.for_each_endpoint(path, |p, e| {
            let mut current_path = *p;
            let clusters = e.get_wildcard_clusters(p.cluster);
            for c in clusters.iter() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_ref());
            }
        });
    }

    pub fn for_each_cluster_mut<T>(&mut self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &mut dyn ClusterType),
    {
        self.for_each_endpoint_mut(path, |p, e| {
            let mut current_path = *p;
            let clusters = e.get_wildcard_clusters_mut(p.cluster);

            for c in clusters.iter_mut() {
                current_path.cluster = Some(c.base().id);
                f(&current_path, c.as_mut());
            }
        });
    }

    pub fn for_each_attribute<T>(&self, path: &GenericPath, mut f: T)
    where
        T: FnMut(&GenericPath, &dyn ClusterType),
    {
        self.for_each_cluster(path, |current_path, c| {
            let mut current_path = *current_path;
            let attributes = c
                .base()
                .get_wildcard_attribute(path.leaf.map(|at| at as u16));
            for a in attributes.iter() {
                current_path.leaf = Some(a.id as u32);
                f(&current_path, c);
            }
        });
    }
}
